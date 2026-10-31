// SSH console server (wolfSSH): RSA-2048 host key generated on first boot, password (local or
// TACACS+) and public key authentication, ssh-copy-id support, UART console sessions.
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/select.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include <wolfssl/wolfcrypt/settings.h>
#include <wolfssl/wolfcrypt/rsa.h>
#include <wolfssl/wolfcrypt/random.h>
#include <wolfssh/ssh.h>
#include <wolfssh/error.h>
#include "app.h"

static const char *TAG = "ssh";

#define MAX_SSH_CONN     3
#define AUTH_TIMEOUT_S   60
#define HOSTKEY_BLOB     "hostkey"

static WOLFSSH_CTX *s_ctx;
static char s_fp[64] = "generating...";
static int s_active;

static char s_banner[2][560];          // double buffer: wolfSSH keeps a pointer to the active one
static int s_banner_ix;

typedef struct {
    int fd;
    char peer[48];
    sp_identity_t id;
    bool authed;
    int64_t started;
} ssh_conn_t;

// ---------------------------------------------------------------- host key
static void put_u32(uint8_t *p, uint32_t v) { p[0] = v >> 24; p[1] = v >> 16; p[2] = v >> 8; p[3] = v; }

static size_t put_mpint(uint8_t *p, const uint8_t *v, size_t n)
{
    while (n > 1 && v[0] == 0) { v++; n--; }
    size_t pad = (v[0] & 0x80) ? 1 : 0;
    put_u32(p, n + pad);
    if (pad) p[4] = 0;
    memcpy(p + 4 + pad, v, n);
    return 4 + pad + n;
}

static void compute_fingerprint(RsaKey *key)
{
    uint8_t e[8], n[512];
    word32 es = sizeof e, ns = sizeof n;
    if (wc_RsaFlattenPublicKey(key, e, &es, n, &ns) != 0) return;
    uint8_t *blob = malloc(4 + 7 + 4 + 9 + 4 + 1 + ns);
    if (!blob) return;
    size_t off = 0;
    put_u32(blob, 7); memcpy(blob + 4, "ssh-rsa", 7); off = 11;
    off += put_mpint(blob + off, e, es);
    off += put_mpint(blob + off, n, ns);
    uint8_t h[32]; unsigned char b[48]; size_t bl = 0;
    mbedtls_sha256(blob, off, h, 0);
    free(blob);
    mbedtls_base64_encode(b, sizeof b, &bl, h, 32);
    while (bl && b[bl - 1] == '=') bl--;
    snprintf(s_fp, sizeof s_fp, "SHA256:%.*s", (int)bl, b);
}

static esp_err_t load_or_create_hostkey(uint8_t **der, size_t *len)
{
    if (config_blob_get(HOSTKEY_BLOB, (void **)der, len) == ESP_OK) return ESP_OK;
    audit("ssh: generating RSA-2048 host key (first boot)");
    int64_t t0 = esp_timer_get_time();
    // Key generation takes a while: run it at idle priority so it can neither starve the web
    // server nor the IDLE task (the task watchdog would reboot and restart the generation).
    UBaseType_t prio = uxTaskPriorityGet(NULL);
    vTaskPrioritySet(NULL, tskIDLE_PRIORITY);
    RsaKey key;
    WC_RNG rng;
    esp_err_t res = ESP_FAIL;
    if (wc_InitRng(&rng) != 0) return ESP_FAIL;
    if (wc_InitRsaKey(&key, NULL) == 0) {
        if (wc_MakeRsaKey(&key, 2048, WC_RSA_EXPONENT, &rng) == 0) {
            uint8_t *buf = malloc(2048);
            int n = buf ? wc_RsaKeyToDer(&key, buf, 2048) : -1;
            if (n > 0 && config_blob_set(HOSTKEY_BLOB, buf, n) == ESP_OK) {
                *der = buf;
                *len = n;
                res = ESP_OK;
                audit("ssh: host key generated in %lld s", (esp_timer_get_time() - t0) / 1000000);
            } else free(buf);
        }
        wc_FreeRsaKey(&key);
    }
    wc_FreeRng(&rng);
    vTaskPrioritySet(NULL, prio);
    return res;
}

static void fingerprint_from_der(const uint8_t *der, size_t len)
{
    RsaKey key;
    word32 idx = 0;
    if (wc_InitRsaKey(&key, NULL) == 0) {
        if (wc_RsaPrivateKeyDecode(der, &idx, &key, len) == 0) compute_fingerprint(&key);
        wc_FreeRsaKey(&key);
    }
}

const char *ssh_host_fingerprint(void) { return s_fp; }

// ---------------------------------------------------------------- authentication
static void copy_field(char *dst, size_t sz, const byte *src, word32 n)
{
    if (n >= sz) n = sz - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

static int user_auth(byte type, WS_UserAuthData *d, void *ctx)
{
    ssh_conn_t *c = ctx;
    char user[SP_USER_LEN + 1];
    if (!c || d->usernameSz > SP_USER_LEN) return WOLFSSH_USERAUTH_INVALID_USER;
    copy_field(user, sizeof user, d->username, d->usernameSz);
    if (!users_claimed() && !g_cfg.tac_en) {
        audit("ssh: login from %s rejected, device not initialised (set the admin password in the web UI)", c->peer);
        return WOLFSSH_USERAUTH_REJECTED;
    }
    if (type == WOLFSSH_USERAUTH_PASSWORD) {
        if (!g_cfg.ssh_password) return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
        char pass[129];
        if (d->sf.password.passwordSz >= sizeof pass) return WOLFSSH_USERAUTH_INVALID_PASSWORD;
        copy_field(pass, sizeof pass, d->sf.password.password, d->sf.password.passwordSz);
        sp_auth_result_t r = auth_password(user, pass, c->peer, "ssh", &c->id);
        memset(pass, 0, sizeof pass);
        if (r == AUTH_OK) { c->authed = true; return WOLFSSH_USERAUTH_SUCCESS; }
        return r == AUTH_LOCKED ? WOLFSSH_USERAUTH_REJECTED : WOLFSSH_USERAUTH_INVALID_PASSWORD;
    }
    if (type == WOLFSSH_USERAUTH_PUBLICKEY) {
        char algo[32];
        copy_field(algo, sizeof algo, d->sf.publicKey.publicKeyType, d->sf.publicKey.publicKeyTypeSz);
        sp_identity_t id;
        if (!auth_pubkey_allowed(user, algo, d->sf.publicKey.publicKey, d->sf.publicKey.publicKeySz, &id))
            return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
        if (d->sf.publicKey.hasSignature) c->id = id;     // signature is verified by wolfSSH
        return WOLFSSH_USERAUTH_SUCCESS;
    }
    return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
}

static int user_auth_result(byte result, WS_UserAuthData *d, void *ctx)
{
    ssh_conn_t *c = ctx;
    if (d && d->type == WOLFSSH_USERAUTH_PUBLICKEY && d->sf.publicKey.hasSignature) {
        char user[SP_USER_LEN + 1];
        copy_field(user, sizeof user, d->username, d->usernameSz);
        if (result == WOLFSSH_USERAUTH_SUCCESS) {
            c->authed = true;
            audit("auth: ssh publickey login '%s' from %s accepted", user, c->peer);
        } else {
            audit("auth: ssh publickey login '%s' from %s FAILED (bad signature)", user, c->peer);
        }
    }
    return WS_SUCCESS;
}

// ---------------------------------------------------------------- I/O helpers
static bool wait_fd(int fd, bool write, int ms)
{
    fd_set fs;
    FD_ZERO(&fs);
    FD_SET(fd, &fs);
    struct timeval tv = { .tv_sec = ms / 1000, .tv_usec = (ms % 1000) * 1000 };
    return select(fd + 1, write ? NULL : &fs, write ? &fs : NULL, NULL, &tv) > 0;
}

static bool want(WOLFSSH *ssh, int ret)
{
    int e = wolfSSH_get_error(ssh);
    return ret == WS_WANT_READ || ret == WS_WANT_WRITE || e == WS_WANT_READ || e == WS_WANT_WRITE ||
           e == WS_REKEYING || ret == WS_REKEYING || e == WS_CHAN_RXD;
}

static bool send_all(WOLFSSH *ssh, int fd, const uint8_t *d, size_t n)
{
    int64_t deadline = esp_timer_get_time() + 30 * 1000000LL;
    while (n) {
        int r = wolfSSH_stream_send(ssh, (byte *)d, n);
        if (r > 0) { d += r; n -= r; continue; }
        if (esp_timer_get_time() > deadline) return false;
        if (r == WS_WINDOW_FULL || wolfSSH_get_error(ssh) == WS_WINDOW_FULL) {
            // let wolfSSH process the peer's window adjust
            wait_fd(fd, false, 50);
            wolfSSH_worker(ssh, NULL);
            continue;
        }
        if (!want(ssh, r)) return false;
        wait_fd(fd, r == WS_WANT_READ, 50);
    }
    return true;
}

static int send_str(WOLFSSH *ssh, int fd, const char *s) { return send_all(ssh, fd, (const uint8_t *)s, strlen(s)); }

// ---------------------------------------------------------------- exec requests
static int handle_exec(WOLFSSH *ssh, ssh_conn_t *c, const char *cmd)
{
    ESP_LOGI(TAG, "exec from %s: %.60s", c->peer, cmd);
    if (strstr(cmd, "authorized_keys")) {
        // ssh-copy-id: read the keys from stdin until EOF and add them to this user
        size_t cap = 8192, len = 0;
        char *buf = calloc(1, cap + 1);
        int64_t deadline = esp_timer_get_time() + 20 * 1000000LL;
        while (buf && len < cap && esp_timer_get_time() < deadline) {
            int r = wolfSSH_stream_read(ssh, (byte *)buf + len, cap - len);
            if (r > 0) { len += r; continue; }
            if (want(ssh, r)) { wait_fd(c->fd, false, 100); continue; }
            break;                      // EOF from ssh-copy-id
        }
        int added = buf ? users_add_keys_text(c->id.name, buf) : -1;
        free(buf);
        audit("ssh: ssh-copy-id by '%s' from %s added %d key(s)", c->id.name, c->peer, added < 0 ? 0 : added);
        if (added < 0) send_str(ssh, c->fd, "serialpill: cannot store keys\n");
        return added < 0 ? 1 : 0;
    }
    if (strcmp(cmd, "exit") == 0 || strcmp(cmd, "true") == 0) return 0;
    if (strcmp(cmd, "break") == 0) { bridge_send_break(); return 0; }
    if (strcmp(cmd, "status") == 0) {
        char s[160];
        snprintf(s, sizeof s, "%s %s, serial %lu %s%s, rx %lu B, tx %lu B\n", sys_device_id(), sys_version(),
                 (unsigned long)g_cfg.baud, g_cfg.format, g_cfg.swap ? " swapped" : "",
                 (unsigned long)bridge_rx_total(), (unsigned long)bridge_tx_total());
        send_str(ssh, c->fd, s);
        return 0;
    }
    send_str(ssh, c->fd, "serialpill: commands: status, break; open an interactive session for the console\n");
    return 127;
}

// ---------------------------------------------------------------- console session
static void console(WOLFSSH *ssh, ssh_conn_t *c)
{
    char who[48];
    snprintf(who, sizeof who, "%s@%s", c->id.name, c->peer);
    sp_session_t *s = bridge_open("ssh", who);
    if (!s) { send_str(ssh, c->fd, "serialpill: too many console sessions\r\n"); return; }
    char hello[200];
    snprintf(hello, sizeof hello, "[serialpill] %s console %lu %s%s - Ctrl+] for menu\r\n", g_cfg.hostname,
             (unsigned long)g_cfg.baud, g_cfg.format, g_cfg.swap ? " (RX/TX swapped)" : "");
    send_str(ssh, c->fd, hello);

    sp_console_t con = { .s = s };
    uint8_t in[256], out[512], rx[512], echo[768];
    char reply[160];
    int64_t last = esp_timer_get_time();
    for (;;) {
        int r = wolfSSH_stream_read(ssh, in, sizeof in);
        if (r > 0) {
            last = esp_timer_get_time();
            int n = console_filter(&con, in, r, out, reply, sizeof reply);
            if (reply[0]) send_str(ssh, c->fd, reply);
            if (n < 0) break;
            bridge_write(s, out, n);
            size_t e = g_cfg.echo ? console_echo(&con, out, n, echo) : 0;
            if (e && !send_all(ssh, c->fd, echo, e)) break;
        } else if (!want(ssh, r)) {
            break;                      // EOF, channel closed or error
        }
        size_t n = bridge_read(s, rx, sizeof rx, 10);
        if (bridge_session_overflowed(s)) send_str(ssh, c->fd, "\r\n[serialpill] output dropped (slow connection)\r\n");
        if (n && !send_all(ssh, c->fd, rx, n)) break;
        if (!n && r <= 0) wait_fd(c->fd, false, 10);
        if (g_cfg.idle_timeout && esp_timer_get_time() - last > (int64_t)g_cfg.idle_timeout * 60000000LL) {
            send_str(ssh, c->fd, "\r\n[serialpill] idle timeout\r\n");
            break;
        }
    }
    bridge_close(s);
}

static void conn_task(void *arg)
{
    ssh_conn_t *c = arg;
    WOLFSSH *ssh = wolfSSH_new(s_ctx);
    if (!ssh) { vTaskDelay(pdMS_TO_TICKS(50)); ssh = wolfSSH_new(s_ctx); }    // first RNG init may fail once
    if (!ssh) { audit("ssh: %s: cannot allocate session", c->peer); goto done; }
    wolfSSH_SetUserAuthCtx(ssh, c);
    wolfSSH_SetUserAuthResultCtx(ssh, c);
    wolfSSH_set_fd(ssh, c->fd);
    int r;
    ESP_LOGI(TAG, "%s: connected", c->peer);
    while ((r = wolfSSH_accept(ssh)) != WS_SUCCESS) {
        if (!want(ssh, r) && wolfSSH_get_error(ssh) != WS_AUTH_PENDING) {
            ESP_LOGI(TAG, "%s: handshake ended: %s", c->peer, wolfSSH_get_error_name(ssh));
            goto done;
        }
        if (esp_timer_get_time() - c->started > AUTH_TIMEOUT_S * 1000000LL) {
            audit("ssh: %s did not authenticate within %d s", c->peer, AUTH_TIMEOUT_S);
            goto done;
        }
        wait_fd(c->fd, wolfSSH_get_error(ssh) == WS_WANT_WRITE, 100);
    }
    if (!c->authed) goto done;
    // accept returns after the first channel request; with "pty-req" first, wait for shell/exec
    WS_SessionType t = wolfSSH_GetSessionType(ssh);
    for (int i = 0; i < 60 && t != WOLFSSH_SESSION_SHELL && t != WOLFSSH_SESSION_EXEC && t != WOLFSSH_SESSION_SUBSYSTEM; i++) {
        wait_fd(c->fd, false, 50);
        r = wolfSSH_worker(ssh, NULL);
        if (r < 0 && !want(ssh, r)) break;
        t = wolfSSH_GetSessionType(ssh);
    }
    ESP_LOGI(TAG, "%s: session type %d", c->peer, t);
    int status = 0;
    if (t == WOLFSSH_SESSION_EXEC) status = handle_exec(ssh, c, wolfSSH_GetSessionCommand(ssh) ?: "");
    else if (t == WOLFSSH_SESSION_SHELL || t == WOLFSSH_SESSION_TERMINAL) console(ssh, c);
    else { send_str(ssh, c->fd, "serialpill: subsystems are not supported\r\n"); status = 1; }
    wolfSSH_stream_exit(ssh, status);
    for (int i = 0; i < 20 && wolfSSH_worker(ssh, NULL) != WS_SUCCESS; i++) wait_fd(c->fd, false, 20);
    wolfSSH_shutdown(ssh);
done:
    ESP_LOGI(TAG, "%s: session ended, stack headroom %u B", c->peer, (unsigned)uxTaskGetStackHighWaterMark(NULL));
    if (ssh) wolfSSH_free(ssh);
    close(c->fd);
    free(c);
    __atomic_fetch_sub(&s_active, 1, __ATOMIC_SEQ_CST);
    vTaskDelete(NULL);
}

static void accept_task(void *arg);

static void listen_task(void *arg)
{
    uint8_t *der = NULL;
    size_t len = 0;
    if (load_or_create_hostkey(&der, &len) != ESP_OK) {
        audit("ssh: host key unavailable, SSH disabled");
        vTaskDelete(NULL);
    }
    fingerprint_from_der(der, len);
    ESP_LOGI(TAG, "host key %s", s_fp);
    if (!g_cfg.ssh_en) {
        // key is generated on first power-on regardless, so its fingerprint is stable
        memset(der, 0, len);
        free(der);
        vTaskDelete(NULL);
    }

    wolfSSH_Init();
    s_ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL);
    wolfSSH_SetUserAuth(s_ctx, user_auth);
    wolfSSH_SetUserAuthResult(s_ctx, user_auth_result);
    ssh_update_banner();
    // modern algorithms only
    wolfSSH_CTX_SetAlgoListKex(s_ctx, "curve25519-sha256,ecdh-sha2-nistp256,ecdh-sha2-nistp384,diffie-hellman-group14-sha256");
    wolfSSH_CTX_SetAlgoListKey(s_ctx, "rsa-sha2-256");
    wolfSSH_CTX_SetAlgoListCipher(s_ctx, "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes128-ctr");
    wolfSSH_CTX_SetAlgoListMac(s_ctx, "hmac-sha2-256,hmac-sha2-512");
    wolfSSH_CTX_SetAlgoListKeyAccepted(s_ctx, "ssh-ed25519,ecdsa-sha2-nistp256,ecdsa-sha2-nistp384,ecdsa-sha2-nistp521,rsa-sha2-256");
    int kr = wolfSSH_CTX_UsePrivateKey_buffer(s_ctx, der, len, WOLFSSH_FORMAT_ASN1);
    if (kr != WS_SUCCESS) {
        audit("ssh: cannot load host key (%d, %u B DER)", kr, (unsigned)len);
        vTaskDelete(NULL);
    }
    memset(der, 0, len);
    free(der);
    // warm-up: the very first wolfSSH_new() after boot can fail while wolfCrypt's RNG initialises
    for (int i = 0; i < 3; i++) {
        WOLFSSH *w = wolfSSH_new(s_ctx);
        if (w) { wolfSSH_free(w); break; }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(g_cfg.ssh_port), .sin_addr.s_addr = htonl(INADDR_ANY) };
    if (bind(lfd, (struct sockaddr *)&a, sizeof a) || listen(lfd, 2)) {
        audit("ssh: cannot listen on port %u", g_cfg.ssh_port);
        vTaskDelete(NULL);
    }
    audit("ssh: listening on port %u, host key %s", g_cfg.ssh_port, s_fp);
    // key generation needed a large stack; accept connections from a small task from here on
    if (xTaskCreate(accept_task, "ssh_accept", 4096, (void *)(intptr_t)lfd, 5, NULL) != pdPASS)
        audit("ssh: cannot start listener");
    vTaskDelete(NULL);
}

static void accept_task(void *arg)
{
    int lfd = (int)(intptr_t)arg, one = 1;
    for (;;) {
        struct sockaddr_in pa;
        socklen_t pl = sizeof pa;
        int fd = accept(lfd, (struct sockaddr *)&pa, &pl);
        if (fd < 0) { vTaskDelay(pdMS_TO_TICKS(100)); continue; }
        char peer[48];
        inet_ntoa_r(pa.sin_addr, peer, sizeof peer);
        if (s_active >= MAX_SSH_CONN || esp_get_free_heap_size() < 45000) {
            audit("ssh: connection from %s refused (busy, %d active, %lu B free)", peer, s_active, (unsigned long)esp_get_free_heap_size());
            close(fd);
            continue;
        }
        fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
        int ka = 1, idle = 60, intvl = 10, cnt = 3;
        setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &ka, sizeof ka);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, &idle, sizeof idle);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, &intvl, sizeof intvl);
        setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, &cnt, sizeof cnt);
        ssh_conn_t *c = calloc(1, sizeof *c);
        if (!c) { close(fd); continue; }
        c->fd = fd;
        c->started = esp_timer_get_time();
        snprintf(c->peer, sizeof c->peer, "%s", peer);
        __atomic_fetch_add(&s_active, 1, __ATOMIC_SEQ_CST);
        if (xTaskCreate(conn_task, "ssh_conn", 8192, c, 5, NULL) != pdPASS) {
            audit("ssh: connection from %s dropped, no memory for session (largest block %u B)", peer,
                  (unsigned)heap_caps_get_largest_free_block(MALLOC_CAP_8BIT));
            __atomic_fetch_sub(&s_active, 1, __ATOMIC_SEQ_CST);
            close(fd);
            free(c);
        }
    }
}

void ssh_update_banner(void)
{
    if (!s_ctx) return;
    int ix = s_banner_ix ^ 1;
    console_banner(s_banner[ix], sizeof s_banner[ix]);
    wolfSSH_CTX_SetBanner(s_ctx, s_banner[ix][0] ? s_banner[ix] : NULL);
    s_banner_ix = ix;
}

esp_err_t ssh_start(void)
{
    return xTaskCreate(listen_task, "ssh_listen", 16384, NULL, 5, NULL) == pdPASS ? ESP_OK : ESP_FAIL;
}
