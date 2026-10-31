// HTTP/HTTPS server core: sessions, authentication, static UI, console terminal (HTTP + WebSocket).
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "esp_https_server.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "mbedtls/base64.h"
#include "web_internal.h"

static const char *TAG = "web";

#define SESSION_MAX     8

extern const uint8_t index_html_start[] asm("_binary_index_html_start");
extern const uint8_t index_html_end[] asm("_binary_index_html_end");
extern const uint8_t xterm_js_start[] asm("_binary_xterm_js_gz_start");
extern const uint8_t xterm_js_end[] asm("_binary_xterm_js_gz_end");
extern const uint8_t xterm_css_start[] asm("_binary_xterm_css_gz_start");
extern const uint8_t xterm_css_end[] asm("_binary_xterm_css_gz_end");
extern const uint8_t xterm_fit_start[] asm("_binary_xterm_addon_fit_js_gz_start");
extern const uint8_t xterm_fit_end[] asm("_binary_xterm_addon_fit_js_gz_end");
extern const uint8_t blades_css_start[] asm("_binary_blades_min_css_gz_start");
extern const uint8_t blades_css_end[] asm("_binary_blades_min_css_gz_end");

static httpd_handle_t s_http, s_https;

// ---------------------------------------------------------------- sessions
typedef struct {
    char token[65];
    sp_identity_t id;
    int64_t last;                   // last use (s); 0 = free slot
} session_t;

static session_t s_sess[SESSION_MAX];
static SemaphoreHandle_t s_lock;

static int64_t now_s(void) { return esp_timer_get_time() / 1000000; }

// a session is valid while used within the configured web timeout (0 = until logout/reboot)
static bool session_valid(const session_t *s)
{
    return s->last && (g_cfg.web_timeout == 0 || now_s() - s->last <= (int64_t)g_cfg.web_timeout * 60);
}

static const char *session_create(const sp_identity_t *id)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    session_t *slot = &s_sess[0];
    for (int i = 0; i < SESSION_MAX; i++) {
        if (!session_valid(&s_sess[i])) { slot = &s_sess[i]; break; }
        if (s_sess[i].last < slot->last) slot = &s_sess[i];        // all in use: replace the least recent
    }
    uint8_t rnd[32];
    esp_fill_random(rnd, sizeof rnd);
    for (int i = 0; i < 32; i++) sprintf(slot->token + 2 * i, "%02x", rnd[i]);
    slot->id = *id;
    slot->last = now_s() ? now_s() : 1;
    xSemaphoreGive(s_lock);
    return slot->token;
}

static bool session_lookup(const char *token, sp_identity_t *id)
{
    bool ok = false;
    if (strlen(token) != 64) return false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < SESSION_MAX; i++) {
        session_t *s = &s_sess[i];
        if (session_valid(s) && strcmp(s->token, token) == 0) {
            s->last = now_s() ? now_s() : 1;                         // sliding expiry
            *id = s->id;
            ok = true;
            break;
        }
    }
    xSemaphoreGive(s_lock);
    return ok;
}

static void session_drop(const char *token)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < SESSION_MAX; i++)
        if (strcmp(s_sess[i].token, token) == 0) memset(&s_sess[i], 0, sizeof s_sess[i]);
    xSemaphoreGive(s_lock);
}

void web_drop_sessions(const char *user)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < SESSION_MAX; i++)
        if (strcmp(s_sess[i].id.name, user) == 0) memset(&s_sess[i], 0, sizeof s_sess[i]);
    xSemaphoreGive(s_lock);
}

// ---------------------------------------------------------------- helpers
bool web_is_https(httpd_req_t *req) { return s_https && req->handle == s_https; }

void web_peer(httpd_req_t *req, char *out, size_t sz)
{
    struct sockaddr_in6 a;
    socklen_t l = sizeof a;
    out[0] = 0;
    if (getpeername(httpd_req_to_sockfd(req), (struct sockaddr *)&a, &l) == 0) {
        if (a.sin6_family == AF_INET) inet_ntoa_r(((struct sockaddr_in *)&a)->sin_addr, out, sz);
        else inet6_ntoa_r(a.sin6_addr, out, sz);
        if (strncasecmp(out, "::ffff:", 7) == 0) memmove(out, out + 7, strlen(out + 7) + 1);   // IPv4-mapped
    }
}

static void security_headers(httpd_req_t *req)
{
    httpd_resp_set_hdr(req, "X-Content-Type-Options", "nosniff");
    httpd_resp_set_hdr(req, "X-Frame-Options", "DENY");
    httpd_resp_set_hdr(req, "Referrer-Policy", "no-referrer");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    if (web_is_https(req)) httpd_resp_set_hdr(req, "Strict-Transport-Security", "max-age=31536000");
}

esp_err_t web_json(httpd_req_t *req, int status, cJSON *body)
{
    char *s = body ? cJSON_PrintUnformatted(body) : NULL;
    cJSON_Delete(body);
    char st[16];
    snprintf(st, sizeof st, "%d", status);
    httpd_resp_set_status(req, status == 200 ? HTTPD_200 : st);
    httpd_resp_set_type(req, "application/json");
    security_headers(req);
    esp_err_t e = httpd_resp_sendstr(req, s ? s : "{}");
    free(s);
    return e;
}

esp_err_t web_error(httpd_req_t *req, int status, const char *msg)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "error", msg);
    return web_json(req, status, o);
}

char *web_body(httpd_req_t *req, size_t max, size_t *len)
{
    if (req->content_len > max) return NULL;
    char *b = malloc(req->content_len + 1);
    size_t got = 0;
    while (b && got < req->content_len) {
        int r = httpd_req_recv(req, b + got, req->content_len - got);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) { free(b); return NULL; }
        got += r;
    }
    if (b) b[got] = 0;
    if (len) *len = got;
    return b;
}

bool web_query(httpd_req_t *req, const char *key, char *out, size_t sz)
{
    char q[256];
    if (httpd_req_get_url_query_str(req, q, sizeof q) != ESP_OK) return false;
    return httpd_query_key_value(q, key, out, sz) == ESP_OK;
}

static bool must_use_https(httpd_req_t *req)
{
    return s_https && g_cfg.https_redirect && !web_is_https(req);
}

bool web_auth(httpd_req_t *req, bool admin, web_auth_t *a)
{
    memset(a, 0, sizeof *a);
    if (must_use_https(req)) { web_error(req, 403, "use HTTPS"); return false; }
    char tok[80];
    size_t tl = sizeof tok;
    bool ok = false;
    if (httpd_req_get_cookie_val(req, "sp_sid", tok, &tl) == ESP_OK && session_lookup(tok, &a->id)) {
        ok = true;
        a->cookie = true;
    } else {
        char hdr[200];
        if (httpd_req_get_hdr_value_str(req, "Authorization", hdr, sizeof hdr) == ESP_OK && strncmp(hdr, "Basic ", 6) == 0) {
            unsigned char dec[150];
            size_t dl = 0;
            if (mbedtls_base64_decode(dec, sizeof dec - 1, &dl, (const unsigned char *)hdr + 6, strlen(hdr + 6)) == 0) {
                dec[dl] = 0;
                char *colon = strchr((char *)dec, ':');
                if (colon) {
                    *colon = 0;
                    char peer[48];
                    web_peer(req, peer, sizeof peer);
                    ok = auth_password((char *)dec, colon + 1, peer, "http", &a->id) == AUTH_OK;
                }
                memset(dec, 0, sizeof dec);
            }
        }
    }
    if (!ok) { web_error(req, 401, "authentication required"); return false; }
    if (a->cookie && req->method != HTTP_GET) {
        char x[24];
        if (httpd_req_get_hdr_value_str(req, "X-Requested-With", x, sizeof x) != ESP_OK || strcmp(x, "SerialPill")) {
            web_error(req, 403, "missing CSRF header");
            return false;
        }
    }
    if (admin && a->id.role != ROLE_ADMIN) { web_error(req, 403, "administrator role required"); return false; }
    return true;
}

static void set_session_cookie(httpd_req_t *req, const char *token, char *buf, size_t sz)
{
    snprintf(buf, sz, "sp_sid=%s; Path=/; HttpOnly; SameSite=Strict%s%s", token,
             web_is_https(req) ? "; Secure" : "", token[0] ? "" : "; Max-Age=0");
    httpd_resp_set_hdr(req, "Set-Cookie", buf);
}

// ---------------------------------------------------------------- static content
static esp_err_t send_static(httpd_req_t *req, const uint8_t *s, const uint8_t *e, const char *type, bool gz)
{
    if (must_use_https(req)) {
        char host[64], loc[160];
        if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof host) != ESP_OK) host[0] = 0;
        char *colon = strchr(host, ':');
        if (colon) *colon = 0;
        snprintf(loc, sizeof loc, "https://%s/", host[0] ? host : wifi_ip());
        httpd_resp_set_status(req, "301 Moved Permanently");
        httpd_resp_set_hdr(req, "Location", loc);
        return httpd_resp_send(req, NULL, 0);
    }
    httpd_resp_set_type(req, type);
    security_headers(req);
    if (gz) {
        httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
        httpd_resp_set_hdr(req, "Cache-Control", "max-age=86400");
    } else {
        httpd_resp_set_hdr(req, "Content-Security-Policy",
                           "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                           "connect-src 'self' ws: wss:; img-src 'self' data:; frame-ancestors 'none'");
    }
    size_t len = e - s;
    if (!gz && len && s[len - 1] == 0) len--;          // EMBED_TXTFILES adds a terminator
    return httpd_resp_send(req, (const char *)s, len);
}

static esp_err_t h_index(httpd_req_t *r) { return send_static(r, index_html_start, index_html_end, "text/html; charset=utf-8", false); }
static esp_err_t h_xjs(httpd_req_t *r) { return send_static(r, xterm_js_start, xterm_js_end, "application/javascript", true); }
static esp_err_t h_xcss(httpd_req_t *r) { return send_static(r, xterm_css_start, xterm_css_end, "text/css", true); }
static esp_err_t h_xfit(httpd_req_t *r) { return send_static(r, xterm_fit_start, xterm_fit_end, "application/javascript", true); }
static esp_err_t h_blades(httpd_req_t *r) { return send_static(r, blades_css_start, blades_css_end, "text/css", true); }

// ---------------------------------------------------------------- login / setup
static esp_err_t h_info(httpd_req_t *req)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "device", sys_device_id());
    cJSON_AddStringToObject(o, "hostname", g_cfg.hostname);
    cJSON_AddStringToObject(o, "version", sys_version());
    cJSON_AddBoolToObject(o, "claimed", users_claimed());
    cJSON_AddStringToObject(o, "banner", g_cfg.banner);
    cJSON_AddStringToObject(o, "name", g_cfg.name);
    cJSON_AddBoolToObject(o, "auth_skip", g_cfg.auth_skip && !users_claimed());
    cJSON_AddBoolToObject(o, "https", s_https != NULL);
    cJSON_AddBoolToObject(o, "secure", web_is_https(req));
    return web_json(req, 200, o);
}

static esp_err_t h_login(httpd_req_t *req)
{
    if (must_use_https(req)) return web_error(req, 403, "use HTTPS");
    char *b = web_body(req, 512, NULL);
    cJSON *j = b ? cJSON_Parse(b) : NULL;
    if (b) { memset(b, 0, strlen(b)); free(b); }
    const char *u = cJSON_GetStringValue(cJSON_GetObjectItem(j, "user"));
    const char *p = cJSON_GetStringValue(cJSON_GetObjectItem(j, "password"));
    if (!u || !p) { cJSON_Delete(j); return web_error(req, 400, "user and password required"); }
    char peer[48];
    web_peer(req, peer, sizeof peer);
    sp_identity_t id;
    sp_auth_result_t r = auth_password(u, p, peer, "web", &id);
    cJSON_Delete(j);
    if (r == AUTH_LOCKED) return web_error(req, 429, "too many failed logins, try again later");
    if (r != AUTH_OK) return web_error(req, 401, "invalid credentials");
    char cookie[160];
    set_session_cookie(req, session_create(&id), cookie, sizeof cookie);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "user", id.name);
    cJSON_AddStringToObject(o, "role", id.role == ROLE_ADMIN ? "admin" : "operator");
    return web_json(req, 200, o);
}

static esp_err_t h_logout(httpd_req_t *req)
{
    char tok[80], cookie[160];
    size_t tl = sizeof tok;
    if (httpd_req_get_cookie_val(req, "sp_sid", tok, &tl) == ESP_OK) session_drop(tok);
    set_session_cookie(req, "", cookie, sizeof cookie);
    return web_json(req, 200, NULL);
}

static esp_err_t h_whoami(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "user", a.id.name);
    cJSON_AddStringToObject(o, "role", a.id.role == ROLE_ADMIN ? "admin" : "operator");
    cJSON_AddBoolToObject(o, "tacacs", a.id.tacacs);
    return web_json(req, 200, o);
}

// first-time setup: only while no administrator password exists
static esp_err_t h_setup(httpd_req_t *req)
{
    if (must_use_https(req)) return web_error(req, 403, "use HTTPS");
    if (users_claimed()) return web_error(req, 409, "already initialised");
    char *b = web_body(req, 512, NULL);
    cJSON *j = b ? cJSON_Parse(b) : NULL;
    if (b) { memset(b, 0, strlen(b)); free(b); }
    const char *ju = cJSON_GetStringValue(cJSON_GetObjectItem(j, "user"));
    const char *p = cJSON_GetStringValue(cJSON_GetObjectItem(j, "password"));
    bool skip = cJSON_IsTrue(cJSON_GetObjectItem(j, "skip"));
    // first-run choices (only while not initialised; changeable later in the settings)
    const cJSON *jr = cJSON_GetObjectItem(j, "https_redirect"), *jt = cJSON_GetObjectItem(j, "telnet_en");
    bool redirect = cJSON_IsBool(jr) ? cJSON_IsTrue(jr) : g_cfg.https_redirect;
    bool telnet = cJSON_IsBool(jt) ? cJSON_IsTrue(jt) : g_cfg.telnet_en;
    bool choices = !g_cfg.auth_skip;        // a later visitor of a skipped device cannot change them
    char u[SP_USER_LEN + 1];
    snprintf(u, sizeof u, "%s", ju ? ju : "admin");        // j is freed below
    esp_err_t e = skip ? ESP_OK : p ? users_set_password(u, p, ROLE_ADMIN, true) : ESP_ERR_INVALID_ARG;
    cJSON_Delete(j);
    if (e == ESP_ERR_INVALID_SIZE) return web_error(req, 400, "password must have 8..128 characters");
    if (e != ESP_OK) return web_error(req, 400, "invalid user name or password");
    char peer[48];
    web_peer(req, peer, sizeof peer);
    bool was_telnet = g_cfg.telnet_en;
    if (choices) { g_cfg.https_redirect = redirect; g_cfg.telnet_en = telnet; }
    if (skip) {
        snprintf(u, sizeof u, "admin");
        if (!g_cfg.auth_skip) audit("setup: password setup skipped from %s - web UI open without login", peer);
        g_cfg.auth_skip = true;
    } else {
        g_cfg.auth_skip = false;
        audit("setup: administrator '%s' created from %s", u, peer);
    }
    config_save();
    if (g_cfg.telnet_en != was_telnet) { if (g_cfg.telnet_en) telnet_start(); else telnet_stop(); }
    sp_identity_t id = { .role = ROLE_ADMIN };
    snprintf(id.name, sizeof id.name, "%s", u);
    char cookie[160];
    set_session_cookie(req, session_create(&id), cookie, sizeof cookie);
    return web_json(req, 200, NULL);
}

// ---------------------------------------------------------------- console over HTTP polling
static esp_err_t h_term_get(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    char v[16];
    uint32_t since = web_query(req, "since", v, sizeof v) ? strtoul(v, NULL, 10) : bridge_rx_total();
    uint8_t *buf = malloc(2048);
    char *b64 = malloc(2800);
    if (!buf || !b64) { free(buf); free(b64); return web_error(req, 500, "out of memory"); }
    uint32_t next, end;
    size_t n = bridge_history(since, buf, 2048, &next, &end), bl = 0;
    mbedtls_base64_encode((unsigned char *)b64, 2800, &bl, buf, n);
    b64[bl] = 0;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "seq", next);
    cJSON_AddNumberToObject(o, "end", end);
    cJSON_AddStringToObject(o, "d", b64);
    free(buf);
    free(b64);
    return web_json(req, 200, o);
}

static esp_err_t h_term_post(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    char v[8];
    if (web_query(req, "break", v, sizeof v)) bridge_send_break();
    size_t n = 0;
    char *b = web_body(req, 4096, &n);
    if (!b) return web_error(req, 413, "max 4096 bytes per request");
    bridge_write(NULL, (uint8_t *)b, n);
    free(b);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddNumberToObject(o, "sent", n);
    return web_json(req, 200, o);
}

// ---------------------------------------------------------------- console over WebSocket
typedef struct {
    httpd_handle_t hd;
    int fd;
    sp_session_t *s;
    sp_console_t con;
    volatile bool closed;
} ws_client_t;

static ws_client_t *s_ws[SP_MAX_SESSIONS];

typedef struct { httpd_handle_t hd; int fd; size_t len; uint8_t data[]; } ws_msg_t;

static void ws_send_work(void *arg)
{
    ws_msg_t *m = arg;
    httpd_ws_frame_t f = { .type = HTTPD_WS_TYPE_BINARY, .payload = m->data, .len = m->len, .final = true };
    httpd_ws_send_frame_async(m->hd, m->fd, &f);
    free(m);
}

static void ws_queue(ws_client_t *c, const void *d, size_t n)
{
    ws_msg_t *m = malloc(sizeof *m + n);
    if (!m) return;
    m->hd = c->hd;
    m->fd = c->fd;
    m->len = n;
    memcpy(m->data, d, n);
    if (httpd_queue_work(c->hd, ws_send_work, m) != ESP_OK) free(m);
}

static void ws_task(void *arg)
{
    ws_client_t *c = arg;
    uint8_t buf[512];
    while (!c->closed && httpd_ws_get_fd_info(c->hd, c->fd) == HTTPD_WS_CLIENT_WEBSOCKET) {
        size_t n = bridge_read(c->s, buf, sizeof buf, 50);
        if (n) ws_queue(c, buf, n);
    }
    for (int i = 0; i < SP_MAX_SESSIONS; i++) if (s_ws[i] == c) s_ws[i] = NULL;
    bridge_close(c->s);
    free(c);
    vTaskDelete(NULL);
}

static ws_client_t *ws_find(httpd_handle_t hd, int fd)
{
    for (int i = 0; i < SP_MAX_SESSIONS; i++)
        if (s_ws[i] && s_ws[i]->hd == hd && s_ws[i]->fd == fd) return s_ws[i];
    return NULL;
}

static bool same_origin(httpd_req_t *req)
{
    char origin[96], host[64];
    if (httpd_req_get_hdr_value_str(req, "Origin", origin, sizeof origin) != ESP_OK) return true;   // non-browser client
    if (httpd_req_get_hdr_value_str(req, "Host", host, sizeof host) != ESP_OK) return false;
    const char *o = strstr(origin, "://");
    return o && strcmp(o + 3, host) == 0;
}

// runs before the 101 response: refuse unauthenticated or cross-site WebSocket upgrades
static esp_err_t ws_pre_handshake(httpd_req_t *req)
{
    char tok[80];
    size_t tl = sizeof tok;
    sp_identity_t id;
    if (!same_origin(req)) {
        httpd_resp_send_err(req, HTTPD_403_FORBIDDEN, "cross-site WebSocket refused");
        return ESP_FAIL;
    }
    if (must_use_https(req) || httpd_req_get_cookie_val(req, "sp_sid", tok, &tl) != ESP_OK || !session_lookup(tok, &id)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "login required");
        return ESP_FAIL;
    }
    return ESP_OK;
}

static esp_err_t h_ws(httpd_req_t *req)
{
    int fd = httpd_req_to_sockfd(req);
    if (req->method == HTTP_GET) {
        // handshake: session cookie and same-origin required
        web_auth_t a;
        char tok[80];
        size_t tl = sizeof tok;
        if (!same_origin(req) || httpd_req_get_cookie_val(req, "sp_sid", tok, &tl) != ESP_OK || !session_lookup(tok, &a.id))
            return ESP_FAIL;
        int slot = -1;
        for (int i = 0; i < SP_MAX_SESSIONS; i++) if (!s_ws[i]) { slot = i; break; }
        char peer[48], who[96];
        web_peer(req, peer, sizeof peer);
        snprintf(who, sizeof who, "%s@%s", a.id.name, peer);
        sp_session_t *s = slot >= 0 ? bridge_open("web", who) : NULL;
        if (!s) return ESP_FAIL;
        ws_client_t *c = calloc(1, sizeof *c);
        if (!c) { bridge_close(s); return ESP_FAIL; }
        c->hd = req->handle;
        c->fd = fd;
        c->s = s;
        c->con.s = s;
        s_ws[slot] = c;
        if (xTaskCreate(ws_task, "ws_term", 3072, c, 5, NULL) != pdPASS) {
            s_ws[slot] = NULL;
            bridge_close(s);
            free(c);
            return ESP_FAIL;
        }
        return ESP_OK;
    }
    httpd_ws_frame_t f = { 0 };
    if (httpd_ws_recv_frame(req, &f, 0) != ESP_OK) return ESP_FAIL;
    ws_client_t *c = ws_find(req->handle, fd);
    if (f.type == HTTPD_WS_TYPE_CLOSE) { if (c) c->closed = true; return ESP_OK; }
    if (!c || !f.len || f.len > 4096) return ESP_OK;
    uint8_t *in = malloc(f.len), *out = malloc(2 * f.len);
    f.payload = in;
    if (in && out && httpd_ws_recv_frame(req, &f, f.len) == ESP_OK) {
        char reply[160];
        int n = console_filter(&c->con, in, f.len, out, reply, sizeof reply);
        if (reply[0]) ws_queue(c, reply, strlen(reply));
        if (n < 0) c->closed = true;
        else bridge_write(c->s, out, n);
    }
    free(in);
    free(out);
    return ESP_OK;
}

static void on_close(httpd_handle_t hd, int fd)
{
    ws_client_t *c = ws_find(hd, fd);
    if (c) c->closed = true;
    close(fd);
}

// ---------------------------------------------------------------- server
static void register_all(httpd_handle_t h)
{
    const httpd_uri_t uris[] = {
        { .uri = "/", .method = HTTP_GET, .handler = h_index },
        { .uri = "/xterm.js", .method = HTTP_GET, .handler = h_xjs },
        { .uri = "/xterm.css", .method = HTTP_GET, .handler = h_xcss },
        { .uri = "/xterm-fit.js", .method = HTTP_GET, .handler = h_xfit },
        { .uri = "/blades.css", .method = HTTP_GET, .handler = h_blades },
        { .uri = "/api/info", .method = HTTP_GET, .handler = h_info },
        { .uri = "/api/login", .method = HTTP_POST, .handler = h_login },
        { .uri = "/api/logout", .method = HTTP_POST, .handler = h_logout },
        { .uri = "/api/whoami", .method = HTTP_GET, .handler = h_whoami },
        { .uri = "/api/setup", .method = HTTP_POST, .handler = h_setup },
        { .uri = "/api/term", .method = HTTP_GET, .handler = h_term_get },
        { .uri = "/api/term", .method = HTTP_POST, .handler = h_term_post },
        { .uri = "/api/ws", .method = HTTP_GET, .handler = h_ws, .is_websocket = true, .handle_ws_control_frames = true,
          .ws_pre_handshake_cb = ws_pre_handshake },
    };
    for (size_t i = 0; i < sizeof uris / sizeof uris[0]; i++) httpd_register_uri_handler(h, &uris[i]);
    api_register(h);
}

bool web_https_running(void)
{
    return s_https != NULL;
}

esp_err_t web_start(void)
{
    s_lock = xSemaphoreCreateMutex();
    httpd_config_t c = HTTPD_DEFAULT_CONFIG();
    c.max_uri_handlers = 48;
    c.max_open_sockets = 7;
    c.stack_size = 8192;
    c.lru_purge_enable = true;
    c.close_fn = on_close;
    c.recv_wait_timeout = 30;
    c.send_wait_timeout = 30;
    esp_err_t e = httpd_start(&s_http, &c);
    if (e != ESP_OK) return e;
    register_all(s_http);

    void *cert = NULL, *key = NULL;
    size_t cl = 0, kl = 0;
    if (config_blob_get("tls_cert", &cert, &cl) == ESP_OK && config_blob_get("tls_key", &key, &kl) == ESP_OK) {
        httpd_ssl_config_t sc = HTTPD_SSL_CONFIG_DEFAULT();
        sc.servercert = cert;
        sc.servercert_len = cl + 1;             // PEM incl. terminator
        sc.prvtkey_pem = key;
        sc.prvtkey_len = kl + 1;
        sc.httpd.max_uri_handlers = 48;
        sc.httpd.max_open_sockets = 3;
        sc.httpd.stack_size = 10240;
        sc.httpd.lru_purge_enable = true;
        sc.httpd.close_fn = on_close;
        sc.httpd.ctrl_port = 32769;
        if (httpd_ssl_start(&s_https, &sc) == ESP_OK) {
            register_all(s_https);
            audit("web: HTTPS enabled on port 443%s", g_cfg.https_redirect ? ", HTTP redirects to HTTPS" : "");
        } else {
            s_https = NULL;
            audit("web: HTTPS failed to start (certificate/key invalid?)");
        }
        // the server keeps pointers to cert/key: intentionally not freed
    } else {
        free(cert);
        free(key);
    }
    ESP_LOGI(TAG, "web server started");
    return ESP_OK;
}
