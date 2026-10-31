// Telnet console server (disabled by default). Same authentication as SSH; credentials travel in
// clear text, so enable it only on trusted management networks.
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/select.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "app.h"

#define IAC   255
#define DONT  254
#define DO    253
#define WONT  252
#define WILL  251
#define SB    250
#define SE    240
#define BRK   243
#define IP    244
#define OPT_ECHO 1
#define OPT_SGA  3

#define MAX_TELNET_CONN 2

typedef struct {
    int fd;
    char peer[48];
    int iac;            // parser state: 0 data, 1 after IAC, 2 option byte, 3 in SB, 4 SB+IAC
    bool cr;            // last data byte was CR (drop the following LF/NUL)
    bool brk;           // client sent IAC BRK
} tconn_t;

static int s_active;
static TaskHandle_t s_listener;
static int s_lfd = -1;

static bool tsend(int fd, const void *d, size_t n)
{
    const uint8_t *p = d;
    while (n) {
        int r = send(fd, p, n, 0);
        if (r <= 0) return false;
        p += r;
        n -= r;
    }
    return true;
}

static bool tsend_str(int fd, const char *s) { return tsend(fd, s, strlen(s)); }

// UART -> client: escape 0xFF
static bool tsend_data(int fd, const uint8_t *d, size_t n)
{
    uint8_t out[600];
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        out[o++] = d[i];
        if (d[i] == IAC) out[o++] = IAC;
        if (o > sizeof out - 2) { if (!tsend(fd, out, o)) return false; o = 0; }
    }
    return tsend(fd, out, o);
}

// strips telnet commands, normalises CR LF / CR NUL to CR; returns data bytes in place
static size_t tfilter(tconn_t *c, uint8_t *b, size_t n)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = b[i];
        switch (c->iac) {
            case 0:
                if (ch == IAC) { c->iac = 1; continue; }
                if (c->cr && (ch == '\n' || ch == 0)) { c->cr = false; continue; }
                c->cr = ch == '\r';
                b[o++] = ch;
                break;
            case 1:
                if (ch == IAC) { b[o++] = IAC; c->iac = 0; }
                else if (ch == SB) c->iac = 3;
                else if (ch >= WILL && ch <= DONT) c->iac = 2;
                else { if (ch == BRK) c->brk = true; c->iac = 0; }
                break;
            case 2: c->iac = 0; break;                     // option negotiation reply: ignore
            case 3: if (ch == IAC) c->iac = 4; break;
            case 4: c->iac = ch == SE ? 0 : 3; break;
        }
    }
    return o;
}

static bool wait_rd(int fd, int ms)
{
    fd_set fs;
    FD_ZERO(&fs);
    FD_SET(fd, &fs);
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return select(fd + 1, &fs, NULL, NULL, &tv) > 0;
}

// reads one line with optional echo; returns false on disconnect/timeout
static bool read_line(tconn_t *c, char *out, size_t sz, bool echo, int timeout_s)
{
    size_t len = 0;
    int64_t deadline = esp_timer_get_time() + (int64_t)timeout_s * 1000000;
    while (esp_timer_get_time() < deadline) {
        if (!wait_rd(c->fd, 200)) continue;
        uint8_t b[64];
        int r = recv(c->fd, b, sizeof b, 0);
        if (r <= 0) return false;
        size_t n = tfilter(c, b, r);
        for (size_t i = 0; i < n; i++) {
            if (b[i] == '\r' || b[i] == '\n') { out[len] = 0; tsend_str(c->fd, "\r\n"); return true; }
            if (b[i] == 0x7f || b[i] == 8) {
                if (len) { len--; if (echo) tsend_str(c->fd, "\b \b"); }
            } else if (b[i] >= 32 && len < sz - 1) {
                out[len++] = b[i];
                if (echo) tsend(c->fd, &b[i], 1);
            }
        }
    }
    return false;
}

static void conn_task(void *arg)
{
    tconn_t *c = arg;
    sp_identity_t id;
    bool ok = false;
    // we echo, character mode
    const uint8_t neg[] = { IAC, WILL, OPT_ECHO, IAC, WILL, OPT_SGA, IAC, DO, OPT_SGA };
    tsend(c->fd, neg, sizeof neg);
    char banner[560];
    console_banner(banner, sizeof banner);
    tsend_str(c->fd, banner);
    if (!users_claimed() && !g_cfg.tac_en) {
        tsend_str(c->fd, "Device not initialised: set the admin password in the web UI first.\r\n");
        goto out;
    }
    for (int attempt = 0; attempt < 3 && !ok; attempt++) {
        char user[SP_USER_LEN + 1], pass[129];
        tsend_str(c->fd, "\r\nlogin: ");
        if (!read_line(c, user, sizeof user, true, 60)) goto out;
        tsend_str(c->fd, "Password: ");
        if (!read_line(c, pass, sizeof pass, false, 60)) goto out;
        sp_auth_result_t r = auth_password(user, pass, c->peer, "telnet", &id);
        memset(pass, 0, sizeof pass);
        if (r == AUTH_OK) ok = true;
        else if (r == AUTH_LOCKED) { tsend_str(c->fd, "Too many failures, try again later.\r\n"); goto out; }
        else tsend_str(c->fd, "Login incorrect\r\n");
    }
    if (!ok) goto out;

    char who[64];
    snprintf(who, sizeof who, "%s@%s", id.name, c->peer);
    sp_session_t *s = bridge_open("telnet", who);
    if (!s) { tsend_str(c->fd, "Too many console sessions.\r\n"); goto out; }
    char hello[160];
    snprintf(hello, sizeof hello, "[serialpill] %s console %lu %s - Ctrl+] for menu\r\n", g_cfg.hostname,
             (unsigned long)g_cfg.baud, g_cfg.format);
    tsend_str(c->fd, hello);
    sp_console_t con = { .s = s };
    uint8_t in[256], out[512], rx[512], echo[768];
    char reply[160];
    int64_t last = esp_timer_get_time();
    for (;;) {
        if (wait_rd(c->fd, 0)) {
            int r = recv(c->fd, in, sizeof in, 0);
            if (r <= 0) break;
            last = esp_timer_get_time();
            size_t n = tfilter(c, in, r);
            if (c->brk) { c->brk = false; bridge_send_break(); }
            int m = console_filter(&con, in, n, out, reply, sizeof reply);
            if (reply[0]) tsend_str(c->fd, reply);
            if (m < 0) break;
            bridge_write(s, out, m);
            size_t e = g_cfg.echo ? console_echo(&con, out, m, echo) : 0;
            if (e && !tsend_data(c->fd, echo, e)) break;
        }
        size_t n = bridge_read(s, rx, sizeof rx, 10);
        if (n && !tsend_data(c->fd, rx, n)) break;
        if (g_cfg.idle_timeout && esp_timer_get_time() - last > (int64_t)g_cfg.idle_timeout * 60000000LL) {
            tsend_str(c->fd, "\r\n[serialpill] idle timeout\r\n");
            break;
        }
    }
    bridge_close(s);
out:
    close(c->fd);
    free(c);
    __atomic_fetch_sub(&s_active, 1, __ATOMIC_SEQ_CST);
    vTaskDelete(NULL);
}

static void listen_task(void *arg)
{
    s_lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(s_lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(g_cfg.telnet_port), .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(s_lfd, (struct sockaddr *)&a, sizeof a) || listen(s_lfd, 2)) {
        audit("telnet: cannot listen on port %u", g_cfg.telnet_port);
        close(s_lfd);
        s_lfd = -1;
        s_listener = NULL;
        vTaskDelete(NULL);
    }
    audit("telnet: listening on port %u (clear text!)", g_cfg.telnet_port);
    for (;;) {
        struct sockaddr_in pa;
        socklen_t pl = sizeof pa;
        int fd = accept(s_lfd, (struct sockaddr *)&pa, &pl);
        if (fd < 0) { if (s_lfd < 0) break; vTaskDelay(pdMS_TO_TICKS(100)); continue; }
        char peer[48];
        inet_ntoa_r(pa.sin_addr, peer, sizeof peer);
        if (s_active >= MAX_TELNET_CONN) { close(fd); continue; }
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof one);
        tconn_t *c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        snprintf(c->peer, sizeof c->peer, "%s", peer);
        __atomic_fetch_add(&s_active, 1, __ATOMIC_SEQ_CST);
        if (xTaskCreate(conn_task, "telnet_conn", 6144, c, 5, NULL) != pdPASS) {
            __atomic_fetch_sub(&s_active, 1, __ATOMIC_SEQ_CST);
            close(fd);
            free(c);
        }
    }
    s_listener = NULL;
    vTaskDelete(NULL);
}

esp_err_t telnet_start(void)
{
    if (!g_cfg.telnet_en || s_listener) return ESP_OK;
    return xTaskCreate(listen_task, "telnet", 4096, NULL, 5, &s_listener) == pdPASS ? ESP_OK : ESP_FAIL;
}

void telnet_stop(void)
{
    if (s_lfd >= 0) {
        int fd = s_lfd;
        s_lfd = -1;
        shutdown(fd, SHUT_RDWR);
        close(fd);
        audit("telnet: stopped");
    }
}
