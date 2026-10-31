// REST API: status, configuration, users and keys, TLS certificate, firmware and Shelly restore.
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_system.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include <time.h>
#include "web_internal.h"

static cJSON *body_json(httpd_req_t *req, size_t max)
{
    char *b = web_body(req, max, NULL);
    cJSON *j = b ? cJSON_Parse(b) : NULL;
    if (b) { memset(b, 0, strlen(b)); free(b); }
    return j;
}

// ---------------------------------------------------------------- status
static esp_err_t h_status(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "device", sys_device_id());
    cJSON_AddStringToObject(o, "version", sys_version());
    cJSON_AddNumberToObject(o, "uptime", (double)(esp_timer_get_time() / 1000000));
    cJSON_AddNumberToObject(o, "heap_free", esp_get_free_heap_size());
    cJSON_AddNumberToObject(o, "heap_min", esp_get_minimum_free_heap_size());
    cJSON_AddStringToObject(o, "slot", esp_ota_get_running_partition()->label);
    const esp_app_desc_t *ad = esp_app_get_description();
    cJSON *b = cJSON_AddObjectToObject(o, "build");
    char sha[17];
    for (int i = 0; i < 8; i++) sprintf(sha + 2 * i, "%02x", ad->app_elf_sha256[i]);
    cJSON_AddStringToObject(b, "date", ad->date);
    cJSON_AddStringToObject(b, "time", ad->time);
    cJSON_AddStringToObject(b, "idf", ad->idf_ver);
    cJSON_AddStringToObject(b, "sha", sha);
    cJSON_AddItemToObject(o, "wifi", wifi_status_json());
    cJSON *s = cJSON_AddObjectToObject(o, "serial");
    cJSON_AddNumberToObject(s, "baud", g_cfg.baud);
    cJSON_AddStringToObject(s, "format", g_cfg.format);
    cJSON_AddBoolToObject(s, "swap", g_cfg.swap);
    cJSON_AddStringToObject(s, "tx_pin", g_cfg.swap ? "GPIO3 (micro-USB pin 3)" : "GPIO4 (micro-USB pin 2)");
    cJSON_AddStringToObject(s, "rx_pin", g_cfg.swap ? "GPIO4 (micro-USB pin 2)" : "GPIO3 (micro-USB pin 3)");
    cJSON_AddNumberToObject(s, "rx_bytes", bridge_rx_total());
    cJSON_AddNumberToObject(s, "tx_bytes", bridge_tx_total());
    cJSON_AddItemToObject(o, "sessions", bridge_sessions_json());
    cJSON_AddStringToObject(o, "ssh_fingerprint", ssh_host_fingerprint());
    void *d; size_t n;
    bool tls = config_blob_get("tls_cert", &d, &n) == ESP_OK;
    cJSON_AddBoolToObject(o, "tls_installed", tls);
    cJSON_AddBoolToObject(o, "tls_selfsigned", tls && tls_is_selfsigned());
    cJSON_AddBoolToObject(o, "https_running", web_https_running());
    if (tls) {
        mbedtls_x509_crt crt;
        mbedtls_x509_crt_init(&crt);
        if (mbedtls_x509_crt_parse(&crt, d, n + 1) == 0) {
            char s[128];
            mbedtls_x509_dn_gets(s, sizeof s, &crt.subject);
            cJSON_AddStringToObject(o, "tls_subject", s);
            mbedtls_x509_dn_gets(s, sizeof s, &crt.issuer);
            cJSON_AddStringToObject(o, "tls_issuer", s);
            snprintf(s, sizeof s, "%04d-%02d-%02d", crt.valid_to.year, crt.valid_to.mon, crt.valid_to.day);
            cJSON_AddStringToObject(o, "tls_valid_to", s);
            uint8_t h[32];
            mbedtls_sha256(crt.raw.p, crt.raw.len, h, 0);
            char fp[100];
            for (int i = 0; i < 32; i++) sprintf(fp + i * 3, "%02X%s", h[i], i < 31 ? ":" : "");
            cJSON_AddStringToObject(o, "tls_sha256", fp);
        }
        mbedtls_x509_crt_free(&crt);
        free(d);
    }
    cJSON_AddNumberToObject(o, "time", (double)time(NULL));
    cJSON *r = cJSON_AddObjectToObject(o, "restore");
    cJSON_AddNumberToObject(r, "progress", shelly_restore_progress());
    cJSON_AddStringToObject(r, "state", shelly_restore_state());
    return web_json(req, 200, o);
}

// ---------------------------------------------------------------- configuration
static esp_err_t h_config_get(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    return web_json(req, 200, config_to_json(false));
}

static esp_err_t h_config_post(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    cJSON *j = body_json(req, 4096);
    if (!j) return web_error(req, 400, "JSON object expected");
    sp_config_t before = g_cfg;
    char err[128] = "";
    esp_err_t e = config_from_json(j, err, sizeof err);
    cJSON_Delete(j);
    if (e != ESP_OK) return web_error(req, 400, err);
    if (config_save() != ESP_OK) { g_cfg = before; return web_error(req, 500, "cannot save configuration"); }
    audit("config: changed by '%s'", a.id.name);
    // applied live: serial port and telnet on/off; everything else on reboot
    if (before.baud != g_cfg.baud || strcmp(before.format, g_cfg.format) || before.swap != g_cfg.swap) bridge_apply_serial();
    if (strcmp(before.banner, g_cfg.banner)) ssh_update_banner();
    if (strcmp(before.ntp_server, g_cfg.ntp_server) || strcmp(before.tz, g_cfg.tz)) time_apply();
    if (before.telnet_en != g_cfg.telnet_en || before.telnet_port != g_cfg.telnet_port) {
        telnet_stop();
        vTaskDelay(pdMS_TO_TICKS(100));
        telnet_start();
    }
    bool reboot = before.wifi_sta != g_cfg.wifi_sta || strcmp(before.ap_ssid, g_cfg.ap_ssid) ||
                  strcmp(before.ap_pass, g_cfg.ap_pass) || strcmp(before.wifi_ssid, g_cfg.wifi_ssid) || strcmp(before.wifi_pass, g_cfg.wifi_pass) ||
                  strcmp(before.hostname, g_cfg.hostname) || before.static_ip != g_cfg.static_ip ||
                  strcmp(before.ip, g_cfg.ip) || strcmp(before.mask, g_cfg.mask) || strcmp(before.gw, g_cfg.gw) ||
                  strcmp(before.dns, g_cfg.dns) || before.usb_bridge != g_cfg.usb_bridge || before.ssh_en != g_cfg.ssh_en ||
                  before.ssh_port != g_cfg.ssh_port || before.https_redirect != g_cfg.https_redirect;
    cJSON *o = config_to_json(false);
    cJSON_AddBoolToObject(o, "reboot_required", reboot);
    return web_json(req, 200, o);
}

// ---------------------------------------------------------------- users & keys
static esp_err_t h_users_get(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    return web_json(req, 200, users_to_json());
}

static esp_err_t h_users_post(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    cJSON *j = body_json(req, 1024);
    const char *u = cJSON_GetStringValue(cJSON_GetObjectItem(j, "user"));
    const char *p = cJSON_GetStringValue(cJSON_GetObjectItem(j, "password"));
    const char *r = cJSON_GetStringValue(cJSON_GetObjectItem(j, "role"));
    esp_err_t e = ESP_ERR_INVALID_ARG;
    if (u) e = users_set_password(u, p && p[0] ? p : NULL, r ? (strcmp(r, "admin") == 0 ? ROLE_ADMIN : ROLE_OPERATOR) : (sp_role_t)-1, true);
    if (e == ESP_OK) {
        audit("users: '%s' %s by '%s'", u, p && p[0] ? "password set" : "updated", a.id.name);
        if (p && p[0] && strcmp(u, a.id.name)) web_drop_sessions(u);
    }
    cJSON_Delete(j);
    if (e == ESP_ERR_INVALID_SIZE) return web_error(req, 400, "password must have 8..128 characters");
    if (e == ESP_ERR_NO_MEM) return web_error(req, 400, "user limit reached");
    if (e != ESP_OK) return web_error(req, 400, "invalid user name (letters, digits, _ - . @)");
    return web_json(req, 200, users_to_json());
}

static esp_err_t h_users_delete(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char u[SP_USER_LEN + 1];
    if (!web_query(req, "user", u, sizeof u)) return web_error(req, 400, "user required");
    esp_err_t e = users_delete(u);
    if (e == ESP_ERR_INVALID_STATE) return web_error(req, 400, "cannot delete the last administrator");
    if (e != ESP_OK) return web_error(req, 404, "no such user");
    web_drop_sessions(u);
    audit("users: '%s' deleted by '%s'", u, a.id.name);
    return web_json(req, 200, users_to_json());
}

static esp_err_t h_keys_post(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    cJSON *j = body_json(req, 4096);
    const char *u = cJSON_GetStringValue(cJSON_GetObjectItem(j, "user"));
    const char *k = cJSON_GetStringValue(cJSON_GetObjectItem(j, "key"));
    if (!u) u = a.id.name;
    char err[96] = "invalid request";
    esp_err_t e = ESP_ERR_INVALID_ARG;
    if (k && (a.id.role == ROLE_ADMIN || strcmp(u, a.id.name) == 0)) e = users_add_key(u, k, err, sizeof err);
    else if (k) snprintf(err, sizeof err, "only administrators can manage keys of other users");
    if (e == ESP_OK) audit("users: SSH key added for '%s' by '%s'", u, a.id.name);
    cJSON_Delete(j);
    if (e != ESP_OK) return web_error(req, 400, err);
    return web_json(req, 200, users_to_json());
}

static esp_err_t h_keys_delete(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    char u[SP_USER_LEN + 1], idx[8];
    if (!web_query(req, "user", u, sizeof u)) snprintf(u, sizeof u, "%s", a.id.name);
    if (!web_query(req, "index", idx, sizeof idx)) return web_error(req, 400, "index required");
    if (a.id.role != ROLE_ADMIN && strcmp(u, a.id.name)) return web_error(req, 403, "administrator role required");
    if (users_del_key(u, atoi(idx)) != ESP_OK) return web_error(req, 404, "no such key");
    audit("users: SSH key %s of '%s' removed by '%s'", idx, u, a.id.name);
    return web_json(req, 200, users_to_json());
}

static esp_err_t h_password(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, false, &a)) return ESP_OK;
    if (a.id.tacacs) return web_error(req, 400, "TACACS+ users change their password on the TACACS+ server");
    cJSON *j = body_json(req, 1024);
    const char *o = cJSON_GetStringValue(cJSON_GetObjectItem(j, "old"));
    const char *n = cJSON_GetStringValue(cJSON_GetObjectItem(j, "new"));
    char peer[48];
    web_peer(req, peer, sizeof peer);
    esp_err_t e = ESP_FAIL;
    if (o && n && auth_password(a.id.name, o, peer, "web", NULL) == AUTH_OK)
        e = users_set_password(a.id.name, n, (sp_role_t)-1, false);
    cJSON_Delete(j);
    if (e == ESP_ERR_INVALID_SIZE) return web_error(req, 400, "password must have 8..128 characters");
    if (e != ESP_OK) return web_error(req, 403, "current password is wrong");
    audit("users: '%s' changed own password", a.id.name);
    return web_json(req, 200, NULL);
}

// ---------------------------------------------------------------- misc
static esp_err_t h_scan(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    return web_json(req, 200, wifi_scan_json());
}

static esp_err_t h_log(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    return web_json(req, 200, audit_to_json());
}

static esp_err_t h_reboot(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    audit("system: reboot requested by '%s'", a.id.name);
    sys_reboot_later(1000);
    return web_json(req, 200, NULL);
}

static esp_err_t h_factory(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char v[8];
    bool keep_key = !(web_query(req, "hostkey", v, sizeof v) && strcmp(v, "1") == 0);
    void *key = NULL; size_t kl = 0;
    if (keep_key) config_blob_get("hostkey", &key, &kl);
    audit("system: factory reset by '%s'%s", a.id.name, keep_key ? " (SSH host key kept)" : "");
    config_factory_reset();
    if (key) { config_blob_set("hostkey", key, kl); memset(key, 0, kl); free(key); }
    sys_reboot_later(1000);
    return web_json(req, 200, NULL);
}

// ---------------------------------------------------------------- TLS certificate
static esp_err_t h_tls_post(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    cJSON *j = body_json(req, 12288);
    const char *cert = cJSON_GetStringValue(cJSON_GetObjectItem(j, "cert"));
    const char *key = cJSON_GetStringValue(cJSON_GetObjectItem(j, "key"));
    const char *err = NULL;
    mbedtls_x509_crt crt;
    mbedtls_pk_context pk;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_x509_crt_init(&crt);
    mbedtls_pk_init(&pk);
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, NULL, 0);
    if (!cert || !key) err = "cert and key (PEM) required";
    else if (mbedtls_x509_crt_parse(&crt, (const unsigned char *)cert, strlen(cert) + 1)) err = "certificate is not valid PEM";
    else if (mbedtls_pk_parse_key(&pk, (const unsigned char *)key, strlen(key) + 1, NULL, 0, mbedtls_ctr_drbg_random, &drbg))
        err = "private key is not valid PEM (unencrypted PKCS#1/PKCS#8/SEC1 expected)";
    else if (mbedtls_pk_check_pair(&crt.pk, &pk, mbedtls_ctr_drbg_random, &drbg)) err = "key does not match the certificate";
    else if (config_blob_set("tls_cert", cert, strlen(cert)) || config_blob_set("tls_key", key, strlen(key))) err = "cannot store";
    if (!err) config_blob_erase("tls_self");
    char subject[128] = "";
    if (!err) mbedtls_x509_dn_gets(subject, sizeof subject, &crt.subject);
    mbedtls_x509_crt_free(&crt);
    mbedtls_pk_free(&pk);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    cJSON_Delete(j);
    if (err) return web_error(req, 400, err);
    audit("web: TLS certificate '%s' installed by '%s'", subject, a.id.name);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddStringToObject(o, "subject", subject);
    cJSON_AddBoolToObject(o, "reboot_required", true);
    return web_json(req, 200, o);
}

static esp_err_t h_tls_delete(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    // HTTPS stays available: back to a fresh self-signed certificate
    if (tls_selfsigned(true) != ESP_OK) return web_error(req, 500, "cannot create the self-signed certificate");
    audit("web: self-signed TLS certificate (re)created by '%s'", a.id.name);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "reboot_required", true);
    return web_json(req, 200, o);
}

// ---------------------------------------------------------------- firmware
// streams a raw request body into a sink, 4 KB at a time
typedef esp_err_t (*sink_fn)(void *ctx, const uint8_t *d, size_t n, char *err, size_t el);

static esp_err_t stream_body(httpd_req_t *req, sink_fn fn, void *ctx, char *err, size_t el)
{
    uint8_t *buf = malloc(4096);
    if (!buf) { snprintf(err, el, "out of memory"); return ESP_ERR_NO_MEM; }
    size_t left = req->content_len;
    esp_err_t e = ESP_OK;
    while (left && e == ESP_OK) {
        int r = httpd_req_recv(req, (char *)buf, left < 4096 ? left : 4096);
        if (r == HTTPD_SOCK_ERR_TIMEOUT) continue;
        if (r <= 0) { snprintf(err, el, "upload interrupted"); e = ESP_FAIL; break; }
        e = fn(ctx, buf, r, err, el);
        left -= r;
    }
    free(buf);
    return e;
}

static esp_err_t ota_sink(void *ctx, const uint8_t *d, size_t n, char *err, size_t el) { return ota_write_chunk(ctx, d, n, err, el); }

static esp_err_t h_firmware(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char err[160] = "";
    void *h = NULL;
    if (!req->content_len) return web_error(req, 400, "empty upload");
    if (ota_begin_upload(req->content_len, &h, err, sizeof err) != ESP_OK) return web_error(req, 400, err);
    audit("firmware: upload by '%s' (%u B)", a.id.name, (unsigned)req->content_len);
    if (stream_body(req, ota_sink, h, err, sizeof err) != ESP_OK) { ota_abort(h); return web_error(req, 400, err); }
    if (ota_finish(h, err, sizeof err) != ESP_OK) return web_error(req, 400, err);
    sys_reboot_later(1500);
    return web_json(req, 200, NULL);
}

static esp_err_t h_firmware_url(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    cJSON *j = body_json(req, 1024);
    const char *url = cJSON_GetStringValue(cJSON_GetObjectItem(j, "url"));
    char err[128] = "link required";
    esp_err_t e = url ? firmware_from_url(url, err, sizeof err) : ESP_ERR_INVALID_ARG;
    if (e == ESP_OK) audit("firmware: update from link requested by '%s'", a.id.name);
    cJSON_Delete(j);
    if (e != ESP_OK) return web_error(req, 400, err);
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "started", true);
    return web_json(req, 200, o);
}

static esp_err_t h_shelly_check(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    cJSON *idx = NULL;
    char err[128];
    if (shelly_check_server(&idx, err, sizeof err) != ESP_OK) return web_error(req, 502, err);
    return web_json(req, 200, idx);
}

static esp_err_t h_shelly_prepare(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char err[128] = "";
    esp_err_t e = shelly_restore_prepare(err, sizeof err);
    cJSON *o = cJSON_CreateObject();
    if (e == ESP_ERR_INVALID_STATE) {
        cJSON_AddBoolToObject(o, "rebooting", true);
        sys_reboot_later(1500);
    } else if (e != ESP_OK) {
        cJSON_Delete(o);
        return web_error(req, 500, err);
    }
    cJSON_AddBoolToObject(o, "ready", e == ESP_OK);
    return web_json(req, 200, o);
}

static esp_err_t h_shelly_restore(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char ch[12] = "stable", err[128] = "";
    web_query(req, "channel", ch, sizeof ch);
    audit("firmware: Shelly restore (%s) requested by '%s'", ch, a.id.name);
    esp_err_t e = shelly_restore_from_server(ch, err, sizeof err);
    cJSON *o = cJSON_CreateObject();
    if (e == ESP_ERR_INVALID_STATE && !err[0]) cJSON_AddBoolToObject(o, "rebooting", true);
    else if (e != ESP_OK) { cJSON_Delete(o); return web_error(req, 400, err[0] ? err : "cannot start restore"); }
    cJSON_AddBoolToObject(o, "started", e == ESP_OK);
    return web_json(req, 200, o);
}

static esp_err_t restore_sink(void *ctx, const uint8_t *d, size_t n, char *err, size_t el) { return shelly_restore_feed(ctx, d, n, err, el); }

static esp_err_t h_shelly_upload(httpd_req_t *req)
{
    web_auth_t a;
    if (!web_auth(req, true, &a)) return ESP_OK;
    char err[160] = "";
    shelly_restore_t *r = shelly_restore_begin(err, sizeof err);
    if (!r) return web_error(req, 409, err);
    audit("firmware: Shelly package upload by '%s' (%u B)", a.id.name, (unsigned)req->content_len);
    esp_err_t e = stream_body(req, restore_sink, r, err, sizeof err);
    if (e == ESP_OK) e = shelly_restore_finish(r, err, sizeof err);
    shelly_restore_abort(r);
    if (e != ESP_OK) return web_error(req, 400, err);
    sys_reboot_later(2000);
    return web_json(req, 200, NULL);
}

void api_register(httpd_handle_t h)
{
    const httpd_uri_t uris[] = {
        { .uri = "/api/status", .method = HTTP_GET, .handler = h_status },
        { .uri = "/api/config", .method = HTTP_GET, .handler = h_config_get },
        { .uri = "/api/config", .method = HTTP_POST, .handler = h_config_post },
        { .uri = "/api/users", .method = HTTP_GET, .handler = h_users_get },
        { .uri = "/api/users", .method = HTTP_POST, .handler = h_users_post },
        { .uri = "/api/users", .method = HTTP_DELETE, .handler = h_users_delete },
        { .uri = "/api/keys", .method = HTTP_POST, .handler = h_keys_post },
        { .uri = "/api/keys", .method = HTTP_DELETE, .handler = h_keys_delete },
        { .uri = "/api/password", .method = HTTP_POST, .handler = h_password },
        { .uri = "/api/wifi/scan", .method = HTTP_GET, .handler = h_scan },
        { .uri = "/api/log", .method = HTTP_GET, .handler = h_log },
        { .uri = "/api/reboot", .method = HTTP_POST, .handler = h_reboot },
        { .uri = "/api/factory-reset", .method = HTTP_POST, .handler = h_factory },
        { .uri = "/api/tls", .method = HTTP_POST, .handler = h_tls_post },
        { .uri = "/api/tls", .method = HTTP_DELETE, .handler = h_tls_delete },
        { .uri = "/api/firmware", .method = HTTP_POST, .handler = h_firmware },
        { .uri = "/api/firmware/url", .method = HTTP_POST, .handler = h_firmware_url },
        { .uri = "/api/shelly/check", .method = HTTP_GET, .handler = h_shelly_check },
        { .uri = "/api/shelly/prepare", .method = HTTP_POST, .handler = h_shelly_prepare },
        { .uri = "/api/shelly/restore", .method = HTTP_POST, .handler = h_shelly_restore },
        { .uri = "/api/shelly/upload", .method = HTTP_POST, .handler = h_shelly_upload },
    };
    for (size_t i = 0; i < sizeof uris / sizeof uris[0]; i++) httpd_register_uri_handler(h, &uris[i]);
}
