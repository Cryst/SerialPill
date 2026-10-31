// TACACS+ authentication client (RFC 8907): ASCII login or PAP, body obfuscation with the shared key.
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "esp_log.h"
#include "esp_random.h"
#include "mbedtls/md5.h"
#include "app.h"

static const char *TAG = "tacacs";

#define TAC_VER_DEFAULT   0xc0
#define TAC_VER_ONE       0xc1          // minor version 1: PAP/CHAP
#define TAC_AUTHEN        0x01
#define TAC_UNENCRYPTED   0x01

enum { ST_PASS = 1, ST_FAIL = 2, ST_GETDATA = 3, ST_GETUSER = 4, ST_GETPASS = 5, ST_RESTART = 6, ST_ERROR = 7, ST_FOLLOW = 0x21 };

typedef struct {
    int fd;
    uint32_t session;
    uint8_t version;
    uint8_t seq;
} tac_t;

// pseudo pad: MD5(session_id, key, version, seq_no [, previous hash]) repeated
static void obfuscate(const tac_t *t, uint8_t seq, uint8_t *body, size_t len)
{
    const char *key = g_cfg.tac_key;
    if (!key[0]) return;
    uint8_t hash[16], sid[4] = { t->session >> 24, t->session >> 16, t->session >> 8, t->session };
    for (size_t off = 0; off < len; off += 16) {
        mbedtls_md5_context c;
        mbedtls_md5_init(&c);
        mbedtls_md5_starts(&c);
        mbedtls_md5_update(&c, sid, 4);
        mbedtls_md5_update(&c, (const uint8_t *)key, strlen(key));
        mbedtls_md5_update(&c, &t->version, 1);
        mbedtls_md5_update(&c, &seq, 1);
        if (off) mbedtls_md5_update(&c, hash, 16);
        mbedtls_md5_finish(&c, hash);
        mbedtls_md5_free(&c);
        for (size_t i = 0; i < 16 && off + i < len; i++) body[off + i] ^= hash[i];
    }
}

static bool io_all(int fd, void *buf, size_t len, bool wr)
{
    uint8_t *p = buf;
    while (len) {
        int n = wr ? send(fd, p, len, 0) : recv(fd, p, len, 0);
        if (n <= 0) return false;
        p += n;
        len -= n;
    }
    return true;
}

static bool send_packet(tac_t *t, uint8_t *body, size_t len)
{
    uint8_t hdr[12] = { t->version, TAC_AUTHEN, ++t->seq, g_cfg.tac_key[0] ? 0 : TAC_UNENCRYPTED,
                        t->session >> 24, t->session >> 16, t->session >> 8, t->session,
                        len >> 24, len >> 16, len >> 8, len };
    obfuscate(t, t->seq, body, len);
    return io_all(t->fd, hdr, 12, true) && io_all(t->fd, body, len, true);
}

// returns malloc'd body (caller frees) or NULL
static uint8_t *recv_packet(tac_t *t, size_t *len)
{
    uint8_t hdr[12];
    if (!io_all(t->fd, hdr, 12, false)) return NULL;
    uint32_t sid = (hdr[4] << 24) | (hdr[5] << 16) | (hdr[6] << 8) | hdr[7];
    uint32_t n = (hdr[8] << 24) | (hdr[9] << 16) | (hdr[10] << 8) | hdr[11];
    if (hdr[1] != TAC_AUTHEN || sid != t->session || hdr[2] != (uint8_t)(t->seq + 1) || n < 6 || n > 4096) {
        ESP_LOGW(TAG, "bad reply header");
        return NULL;
    }
    t->seq = hdr[2];
    uint8_t *b = malloc(n);
    if (!b || !io_all(t->fd, b, n, false)) { free(b); return NULL; }
    if (!(hdr[3] & TAC_UNENCRYPTED)) obfuscate(t, t->seq, b, n);
    *len = n;
    return b;
}

static int connect_server(void)
{
    char port[8];
    snprintf(port, sizeof port, "%u", g_cfg.tac_port);
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    if (getaddrinfo(g_cfg.tac_host, port, &hints, &res) != 0 || !res) return -1;
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd >= 0) {
        struct timeval tv = { .tv_sec = g_cfg.tac_timeout };
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
        if (connect(fd, res->ai_addr, res->ai_addrlen) != 0) { close(fd); fd = -1; }
    }
    freeaddrinfo(res);
    return fd;
}

tac_result_t tacacs_authenticate(const char *user, const char *pass, const char *port, const char *rem, char *msg, size_t ml)
{
    tac_t t = { .session = esp_random() | 1, .version = g_cfg.tac_pap ? TAC_VER_ONE : TAC_VER_DEFAULT };
    msg[0] = 0;
    t.fd = connect_server();
    if (t.fd < 0) { snprintf(msg, ml, "cannot connect to %s:%u", g_cfg.tac_host, g_cfg.tac_port); return TAC_ERROR; }

    size_t ul = strlen(user), pl = strlen(port), rl = strlen(rem), dl = g_cfg.tac_pap ? strlen(pass) : 0;
    size_t len = 8 + ul + pl + rl + dl;
    uint8_t *b = malloc(len);
    tac_result_t res = TAC_ERROR;
    if (!b) goto out;
    // START: action LOGIN, priv 1, type ASCII(1)/PAP(2), service LOGIN(1)
    uint8_t *p = b;
    *p++ = 1; *p++ = 1; *p++ = g_cfg.tac_pap ? 2 : 1; *p++ = 1;
    *p++ = ul; *p++ = pl; *p++ = rl; *p++ = dl;
    memcpy(p, user, ul); p += ul;
    memcpy(p, port, pl); p += pl;
    memcpy(p, rem, rl); p += rl;
    memcpy(p, pass, dl);
    bool ok = send_packet(&t, b, len);
    memset(b, 0, len);
    free(b);
    if (!ok) { snprintf(msg, ml, "send failed"); goto out; }

    for (int round = 0; round < 6; round++) {
        size_t n;
        uint8_t *r = recv_packet(&t, &n);
        if (!r) { snprintf(msg, ml, "no/invalid reply (check shared key)"); goto out; }
        uint8_t status = r[0];
        size_t mlen = (r[2] << 8) | r[3];
        if (6 + mlen <= n && mlen) snprintf(msg, ml, "%.*s", (int)mlen, (const char *)r + 6);
        free(r);
        if (status == ST_PASS) { res = TAC_PASS; goto out; }
        if (status == ST_FAIL) { res = TAC_FAIL; goto out; }
        if (status != ST_GETUSER && status != ST_GETPASS && status != ST_GETDATA) {
            if (!msg[0]) snprintf(msg, ml, "server status 0x%02x", status);
            goto out;
        }
        // CONTINUE with user name or password
        const char *data = status == ST_GETUSER ? user : pass;
        size_t d = strlen(data);
        uint8_t *c = malloc(5 + d);
        if (!c) goto out;
        c[0] = d >> 8; c[1] = d; c[2] = 0; c[3] = 0; c[4] = 0;     // user_msg_len = d, data_len = 0, flags
        memcpy(c + 5, data, d);
        ok = send_packet(&t, c, 5 + d);
        memset(c, 0, 5 + d);
        free(c);
        if (!ok) { snprintf(msg, ml, "send failed"); goto out; }
    }
    snprintf(msg, ml, "too many rounds");
out:
    close(t.fd);
    return res;
}
