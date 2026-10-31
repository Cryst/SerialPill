// Local users, password hashing (PBKDF2-HMAC-SHA256), SSH authorized keys and login policy.
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/md.h"
#include "mbedtls/base64.h"
#include "mbedtls/sha256.h"
#include "mbedtls/constant_time.h"
#include "app.h"

static const char *TAG = "users";
#define PBKDF2_ITER   10000
#define USERS_BLOB    "users"

static cJSON *s_users;          // {"users":[{"u":..,"r":0|1,"h":..,"k":[..]}]}
static SemaphoreHandle_t s_lock;

// ---------------------------------------------------------------- persistence
static cJSON *arr(void) { return cJSON_GetObjectItem(s_users, "users"); }

static esp_err_t save(void)
{
    char *s = cJSON_PrintUnformatted(s_users);
    if (!s) return ESP_ERR_NO_MEM;
    esp_err_t e = config_blob_set(USERS_BLOB, s, strlen(s));
    free(s);
    return e;
}

esp_err_t users_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    void *d; size_t n;
    if (config_blob_get(USERS_BLOB, &d, &n) == ESP_OK) {
        s_users = cJSON_Parse(d);
        free(d);
    }
    if (!s_users || !cJSON_IsArray(arr())) {
        cJSON_Delete(s_users);
        s_users = cJSON_CreateObject();
        cJSON_AddArrayToObject(s_users, "users");
    }
    return ESP_OK;
}

static cJSON *find(const char *user)
{
    cJSON *u;
    cJSON_ArrayForEach(u, arr()) {
        const cJSON *n = cJSON_GetObjectItem(u, "u");
        if (cJSON_IsString(n) && strcmp(n->valuestring, user) == 0) return u;
    }
    return NULL;
}

static const char *str(const cJSON *u, const char *k)
{
    const cJSON *v = cJSON_GetObjectItem(u, k);
    return cJSON_IsString(v) ? v->valuestring : "";
}

bool users_claimed(void)
{
    bool r = false;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON *u;
    cJSON_ArrayForEach(u, arr())
        if (cJSON_GetObjectItem(u, "r")->valueint == ROLE_ADMIN && str(u, "h")[0]) r = true;
    xSemaphoreGive(s_lock);
    return r;
}

static bool valid_username(const char *s)
{
    size_t n = strlen(s);
    if (n == 0 || n > SP_USER_LEN) return false;
    for (; *s; s++)
        if (!(isalnum((unsigned char)*s) || *s == '_' || *s == '-' || *s == '.' || *s == '@')) return false;
    return true;
}

// ---------------------------------------------------------------- hashing
static void b64(const uint8_t *in, size_t n, char *out, size_t outsz)
{
    size_t o = 0;
    mbedtls_base64_encode((unsigned char *)out, outsz, &o, in, n);
    out[o] = 0;
}

static esp_err_t hash_password(const char *pass, char *out, size_t outsz)
{
    uint8_t salt[16], dk[32];
    esp_fill_random(salt, sizeof salt);
    if (mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pass, strlen(pass), salt, sizeof salt,
                                      PBKDF2_ITER, sizeof dk, dk) != 0) return ESP_FAIL;
    char s64[32], d64[48];
    b64(salt, sizeof salt, s64, sizeof s64);
    b64(dk, sizeof dk, d64, sizeof d64);
    snprintf(out, outsz, "pbkdf2-sha256$%d$%s$%s", PBKDF2_ITER, s64, d64);
    return ESP_OK;
}

static bool verify_hash(const char *stored, const char *user, const char *pass)
{
    if (strncmp(stored, "pbkdf2-sha256$", 14) == 0) {
        int iter = atoi(stored + 14);
        const char *p1 = strchr(stored + 14, '$');
        const char *p2 = p1 ? strchr(p1 + 1, '$') : NULL;
        if (!p2 || iter < 1000 || iter > 1000000) return false;
        uint8_t salt[32], want[64], got[64];
        size_t sn = 0, wn = 0;
        if (mbedtls_base64_decode(salt, sizeof salt, &sn, (const unsigned char *)p1 + 1, p2 - p1 - 1) ||
            mbedtls_base64_decode(want, sizeof want, &wn, (const unsigned char *)p2 + 1, strlen(p2 + 1)) || wn == 0)
            return false;
        if (mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pass, strlen(pass), salt, sn, iter, wn, got))
            return false;
        return mbedtls_ct_memcmp(want, got, wn) == 0;
    }
    if (strncmp(stored, "shelly-ha1$", 11) == 0) {
        // imported from stock Shelly: ha1 = sha256("admin:<realm>:<password>")
        const char *realm = stored + 11, *p = strchr(realm, '$');
        if (!p || strlen(p + 1) != 64) return false;
        char buf[200];
        int n = snprintf(buf, sizeof buf, "%s:%.*s:%s", user, (int)(p - realm), realm, pass);
        if (n <= 0 || n >= (int)sizeof buf) return false;
        uint8_t h[32]; char hex[65];
        mbedtls_sha256((const unsigned char *)buf, n, h, 0);
        for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
        return mbedtls_ct_memcmp(hex, p + 1, 64) == 0;
    }
    return false;
}

esp_err_t users_set_password(const char *user, const char *pass, sp_role_t role, bool create)
{
    if (!valid_username(user)) return ESP_ERR_INVALID_ARG;
    if (pass && (strlen(pass) < 8 || strlen(pass) > 128)) return ESP_ERR_INVALID_SIZE;
    char h[128] = "";
    if (pass && hash_password(pass, h, sizeof h) != ESP_OK) return ESP_FAIL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = ESP_OK;
    cJSON *u = find(user);
    if (!u) {
        if (!create) e = ESP_ERR_NOT_FOUND;
        else if (cJSON_GetArraySize(arr()) >= SP_MAX_USERS) e = ESP_ERR_NO_MEM;
        else {
            u = cJSON_CreateObject();
            cJSON_AddStringToObject(u, "u", user);
            cJSON_AddNumberToObject(u, "r", role);
            cJSON_AddStringToObject(u, "h", "");
            cJSON_AddArrayToObject(u, "k");
            cJSON_AddItemToArray(arr(), u);
        }
    }
    if (e == ESP_OK) {
        if (pass) cJSON_ReplaceItemInObject(u, "h", cJSON_CreateString(h));
        if ((int)role >= 0) cJSON_ReplaceItemInObject(u, "r", cJSON_CreateNumber(role));
        e = save();
    }
    xSemaphoreGive(s_lock);
    return e;
}

esp_err_t users_delete(const char *user)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = ESP_ERR_NOT_FOUND;
    int i = 0; cJSON *u;
    cJSON_ArrayForEach(u, arr()) {
        if (strcmp(str(u, "u"), user) == 0) {
            // never delete the last administrator
            int admins = 0; cJSON *x;
            cJSON_ArrayForEach(x, arr()) if (cJSON_GetObjectItem(x, "r")->valueint == ROLE_ADMIN && str(x, "h")[0]) admins++;
            if (cJSON_GetObjectItem(u, "r")->valueint == ROLE_ADMIN && str(u, "h")[0] && admins <= 1) { e = ESP_ERR_INVALID_STATE; break; }
            cJSON_DeleteItemFromArray(arr(), i);
            e = save();
            break;
        }
        i++;
    }
    xSemaphoreGive(s_lock);
    return e;
}

static void key_fingerprint(const char *line, char *out, size_t outsz)
{
    // SHA256:<base64> of the key blob, like ssh-keygen -l
    const char *sp = strchr(line, ' ');
    out[0] = 0;
    if (!sp) return;
    const char *e = strchr(sp + 1, ' ');
    size_t n = e ? (size_t)(e - sp - 1) : strlen(sp + 1);
    uint8_t *blob = malloc(n);
    size_t bn = 0;
    if (blob && mbedtls_base64_decode(blob, n, &bn, (const unsigned char *)sp + 1, n) == 0) {
        uint8_t h[32]; char b[48];
        mbedtls_sha256(blob, bn, h, 0);
        b64(h, 32, b, sizeof b);
        char *eq = strchr(b, '=');
        if (eq) *eq = 0;
        snprintf(out, outsz, "SHA256:%s", b);
    }
    free(blob);
}

cJSON *users_to_json(void)
{
    cJSON *out = cJSON_CreateArray();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON *u;
    cJSON_ArrayForEach(u, arr()) {
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "user", str(u, "u"));
        cJSON_AddStringToObject(o, "role", cJSON_GetObjectItem(u, "r")->valueint == ROLE_ADMIN ? "admin" : "operator");
        const char *h = str(u, "h");
        cJSON_AddStringToObject(o, "password", !h[0] ? "none" : strncmp(h, "shelly-ha1$", 11) == 0 ? "shelly" : "set");
        cJSON *keys = cJSON_AddArrayToObject(o, "keys");
        cJSON *k;
        cJSON_ArrayForEach(k, cJSON_GetObjectItem(u, "k")) {
            cJSON *ko = cJSON_CreateObject();
            char fp[64];
            key_fingerprint(k->valuestring, fp, sizeof fp);
            const char *sp = strchr(k->valuestring, ' ');
            const char *cm = sp ? strchr(sp + 1, ' ') : NULL;
            char type[32];
            snprintf(type, sizeof type, "%.*s", sp ? (int)(sp - k->valuestring) : 0, k->valuestring);
            cJSON_AddStringToObject(ko, "type", type);
            cJSON_AddStringToObject(ko, "fingerprint", fp);
            cJSON_AddStringToObject(ko, "comment", cm ? cm + 1 : "");
            cJSON_AddItemToArray(keys, ko);
        }
        cJSON_AddItemToArray(out, o);
    }
    xSemaphoreGive(s_lock);
    return out;
}

// ---------------------------------------------------------------- authorized keys
static const char *KEY_TYPES[] = {
    "ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256", "ecdsa-sha2-nistp384", "ecdsa-sha2-nistp521", NULL
};

// Normalises one authorized_keys line to "type base64 [comment]"; returns false if unusable.
static bool parse_key_line(const char *line, char *out, size_t outsz)
{
    while (*line == ' ' || *line == '\t') line++;
    if (!*line || *line == '#') return false;
    char type[32];
    const char *sp = strpbrk(line, " \t");
    if (!sp || (size_t)(sp - line) >= sizeof type) return false;
    memcpy(type, line, sp - line);
    type[sp - line] = 0;
    bool known = false;
    for (int i = 0; KEY_TYPES[i]; i++) if (strcmp(type, KEY_TYPES[i]) == 0) known = true;
    if (!known) return false;            // options prefixes (from="...") are not supported
    while (*sp == ' ' || *sp == '\t') sp++;
    const char *e = strpbrk(sp, " \t\r\n");
    size_t n = e ? (size_t)(e - sp) : strlen(sp);
    if (n < 16 || n > 1200) return false;
    // the blob must decode and start with the same key type string
    uint8_t *blob = malloc(n);
    size_t bn = 0;
    bool ok = blob && mbedtls_base64_decode(blob, n, &bn, (const unsigned char *)sp, n) == 0 && bn > 4 + strlen(type) &&
              (size_t)((blob[0] << 24) | (blob[1] << 16) | (blob[2] << 8) | blob[3]) == strlen(type) &&
              memcmp(blob + 4, type, strlen(type)) == 0;
    free(blob);
    if (!ok) return false;
    char comment[64] = "";
    if (e) {
        while (*e == ' ' || *e == '\t') e++;
        size_t cn = strcspn(e, "\r\n");
        if (cn >= sizeof comment) cn = sizeof comment - 1;
        memcpy(comment, e, cn);
        comment[cn] = 0;
    }
    int w = snprintf(out, outsz, "%s %.*s%s%s", type, (int)n, sp, comment[0] ? " " : "", comment);
    return w > 0 && (size_t)w < outsz;
}

static esp_err_t add_key_locked(const char *user, const char *norm)
{
    cJSON *u = find(user);
    if (!u) {
        // key-only account (e.g. a TACACS+ user who ran ssh-copy-id)
        if (cJSON_GetArraySize(arr()) >= SP_MAX_USERS) return ESP_ERR_NO_MEM;
        u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "u", user);
        cJSON_AddNumberToObject(u, "r", ROLE_OPERATOR);
        cJSON_AddStringToObject(u, "h", "");
        cJSON_AddArrayToObject(u, "k");
        cJSON_AddItemToArray(arr(), u);
    }
    cJSON *keys = cJSON_GetObjectItem(u, "k");
    size_t blob_len = strcspn(strchr(norm, ' ') + 1, " ");
    cJSON *k;
    cJSON_ArrayForEach(k, keys) {
        const char *s = strchr(k->valuestring, ' ');
        if (s && strncmp(s + 1, strchr(norm, ' ') + 1, blob_len) == 0) return ESP_ERR_INVALID_STATE;   // duplicate
    }
    if (cJSON_GetArraySize(keys) >= SP_MAX_KEYS) return ESP_ERR_NO_MEM;
    cJSON_AddItemToArray(keys, cJSON_CreateString(norm));
    return ESP_OK;
}

esp_err_t users_add_key(const char *user, const char *line, char *err, size_t el)
{
    char norm[1400];
    if (!valid_username(user)) { snprintf(err, el, "invalid user name"); return ESP_ERR_INVALID_ARG; }
    if (!parse_key_line(line, norm, sizeof norm)) { snprintf(err, el, "unsupported or malformed public key"); return ESP_ERR_INVALID_ARG; }
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = add_key_locked(user, norm);
    if (e == ESP_OK) e = save();
    xSemaphoreGive(s_lock);
    if (e == ESP_ERR_INVALID_STATE) snprintf(err, el, "key already present");
    else if (e == ESP_ERR_NO_MEM) snprintf(err, el, "too many keys/users");
    else if (e != ESP_OK) snprintf(err, el, "%s", esp_err_to_name(e));
    return e;
}

int users_add_keys_text(const char *user, const char *text)
{
    int added = 0;
    if (!valid_username(user)) return -1;
    char *norm = malloc(1400);
    if (!norm) return -1;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (const char *l = text; l && *l;) {
        const char *nl = strchr(l, '\n');
        size_t n = nl ? (size_t)(nl - l) : strlen(l);
        char *line = strndup(l, n);
        if (line && parse_key_line(line, norm, 1400) && add_key_locked(user, norm) == ESP_OK) added++;
        free(line);
        l = nl ? nl + 1 : NULL;
    }
    if (added) save();
    xSemaphoreGive(s_lock);
    free(norm);
    return added;
}

esp_err_t users_del_key(const char *user, int index)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = ESP_ERR_NOT_FOUND;
    cJSON *u = find(user);
    cJSON *keys = u ? cJSON_GetObjectItem(u, "k") : NULL;
    if (keys && index >= 0 && index < cJSON_GetArraySize(keys)) {
        cJSON_DeleteItemFromArray(keys, index);
        e = save();
    }
    xSemaphoreGive(s_lock);
    return e;
}

bool auth_pubkey_allowed(const char *user, const char *algo, const uint8_t *blob, size_t len, sp_identity_t *id)
{
    bool ok = false;
    char *b = malloc(len * 4 / 3 + 8);
    if (!b) return false;
    b64(blob, len, b, len * 4 / 3 + 8);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON *u = find(user);
    if (u) {
        cJSON *k;
        cJSON_ArrayForEach(k, cJSON_GetObjectItem(u, "k")) {
            const char *sp = strchr(k->valuestring, ' ');
            if (!sp) continue;
            size_t n = strcspn(sp + 1, " ");
            if (n == strlen(b) && memcmp(sp + 1, b, n) == 0) { ok = true; break; }
        }
        if (ok && id) {
            snprintf(id->name, sizeof id->name, "%s", user);
            id->role = cJSON_GetObjectItem(u, "r")->valueint;
            id->tacacs = !str(u, "h")[0];
        }
    }
    xSemaphoreGive(s_lock);
    free(b);
    (void)algo;
    return ok;
}

esp_err_t users_import_shelly_ha1(const char *realm, const char *ha1)
{
    if (strlen(ha1) != 64 || strlen(realm) > 64) return ESP_ERR_INVALID_ARG;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    esp_err_t e = ESP_OK;
    if (!find("admin")) {
        char h[160];
        snprintf(h, sizeof h, "shelly-ha1$%s$%s", realm, ha1);
        cJSON *u = cJSON_CreateObject();
        cJSON_AddStringToObject(u, "u", "admin");
        cJSON_AddNumberToObject(u, "r", ROLE_ADMIN);
        cJSON_AddStringToObject(u, "h", h);
        cJSON_AddArrayToObject(u, "k");
        cJSON_AddItemToArray(arr(), u);
        e = save();
    }
    xSemaphoreGive(s_lock);
    return e;
}

// ---------------------------------------------------------------- brute-force protection
typedef struct { char peer[48]; uint8_t fails; int64_t until; } lock_t;
static lock_t s_locks[16];

static lock_t *lock_slot(const char *peer, bool create)
{
    lock_t *free_slot = NULL, *oldest = &s_locks[0];
    for (int i = 0; i < 16; i++) {
        if (strcmp(s_locks[i].peer, peer) == 0) return &s_locks[i];
        if (!s_locks[i].peer[0] && !free_slot) free_slot = &s_locks[i];
        if (s_locks[i].until < oldest->until) oldest = &s_locks[i];
    }
    if (!create) return NULL;
    lock_t *l = free_slot ? free_slot : oldest;
    memset(l, 0, sizeof *l);
    snprintf(l->peer, sizeof l->peer, "%s", peer);
    return l;
}

static bool peer_locked(const char *peer)
{
    lock_t *l = lock_slot(peer, false);
    return l && l->until > esp_timer_get_time();
}

static void peer_result(const char *peer, bool ok)
{
    lock_t *l = lock_slot(peer, !ok);
    if (!l) return;
    if (ok) { memset(l, 0, sizeof *l); return; }
    if (++l->fails >= 5) {
        int shift = l->fails - 5 > 4 ? 4 : l->fails - 5;
        int64_t secs = 60LL << shift;                  // 1, 2, 4, 8, 16 minutes
        l->until = esp_timer_get_time() + secs * 1000000LL;
        audit("auth: %s locked out for %lld s after %u failures", peer, secs, l->fails);
    }
}

static bool local_check(const char *user, const char *pass, sp_identity_t *id)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    cJSON *u = find(user);
    char *h = u ? strdup(str(u, "h")) : NULL;
    int role = u ? cJSON_GetObjectItem(u, "r")->valueint : 0;
    xSemaphoreGive(s_lock);
    bool ok = h && h[0] && verify_hash(h, user, pass);
    if (!h || !h[0]) {
        // spend comparable time for unknown users to avoid user enumeration by timing
        uint8_t dk[32];
        mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256, (const unsigned char *)pass, strlen(pass),
                                      (const unsigned char *)"serialpill-dummy", 16, PBKDF2_ITER, sizeof dk, dk);
    }
    if (ok && strncmp(h, "shelly-ha1$", 11) == 0) {
        users_set_password(user, pass, -1, false);    // upgrade imported Shelly hash to PBKDF2
    }
    free(h);
    if (ok && id) {
        snprintf(id->name, sizeof id->name, "%s", user);
        id->role = role;
        id->tacacs = false;
    }
    return ok;
}

sp_auth_result_t auth_password(const char *user, const char *pass, const char *peer, const char *service, sp_identity_t *id)
{
    if (peer_locked(peer)) {
        audit("auth: %s login for '%s' from %s refused (locked out)", service, user, peer);
        return AUTH_LOCKED;
    }
    if (!valid_username(user) || strlen(pass) > 128) {
        peer_result(peer, false);
        return AUTH_FAIL;
    }
    bool ok = false;
    const char *how = "local";
    // Local accounts with a password are checked first, so a local (break-glass) administrator can
    // always log in, even when the TACACS+ server does not know it. Everyone else goes to TACACS+.
    bool local_pw = false;
    if (g_cfg.tac_en) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        cJSON *u = find(user);
        local_pw = u && str(u, "h")[0];
        xSemaphoreGive(s_lock);
    }
    if (g_cfg.tac_en && local_pw && local_check(user, pass, id)) {
        ok = true;
    } else if (g_cfg.tac_en) {
        char msg[96] = "";
        tac_result_t r = tacacs_authenticate(user, pass, service, peer, msg, sizeof msg);
        if (r == TAC_PASS) {
            ok = true;
            how = "tacacs";
            if (id) {
                snprintf(id->name, sizeof id->name, "%s", user);
                id->role = g_cfg.tac_admin ? ROLE_ADMIN : ROLE_OPERATOR;
                id->tacacs = true;
            }
        } else if (r == TAC_ERROR && g_cfg.tac_fallback) {
            audit("auth: TACACS+ unavailable (%s), falling back to local users", msg);
            ok = local_check(user, pass, id);
            how = "local-fallback";
        } else {
            how = r == TAC_FAIL ? "tacacs" : "tacacs-error";
        }
    } else {
        ok = local_check(user, pass, id);
    }
    peer_result(peer, ok);
    audit("auth: %s login '%s' from %s %s (%s)", service, user, peer, ok ? "accepted" : "FAILED", how);
    if (!ok) vTaskDelay(pdMS_TO_TICKS(500 + (esp_random() % 500)));
    return ok ? AUTH_OK : AUTH_FAIL;
}
