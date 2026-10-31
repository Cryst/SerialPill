// Firmware management:
//  * SerialPill updates (raw app image upload) with automatic rollback if the new image fails;
//  * restore of the official Shelly firmware from an official package (zip), streamed either from
//    an upload or from Shelly's update server. Every part is checked against the SHA-256 in the
//    package manifest before the boot regions are touched.
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_ota_ops.h"
#include "esp_app_desc.h"
#include "esp_flash.h"
#include "esp_partition.h"
#include "esp_image_format.h"
#include "esp_http_client.h"
#include "esp_crt_bundle.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "mbedtls/sha256.h"
#include "esp_littlefs.h"
#include <stdio.h>
#include "app.h"

static const char *TAG = "ota";

// ================================================================ SerialPill self-update
// An administrator starting a firmware operation proves the running image works: confirm it, so
// the OTA layer allows writing the other slot (otherwise refused while rollback is pending).
static void confirm_running(void)
{
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY) {
        esp_ota_mark_app_valid_cancel_rollback();
        audit("firmware: running image confirmed (firmware operation started)");
    }
}

typedef struct {
    esp_ota_handle_t h;
    const esp_partition_t *part;
    size_t written;
    uint8_t head[64];
    size_t headlen;
    bool checked;
} self_ota_t;

static bool check_header(const uint8_t *d, size_t n, char *err, size_t el)
{
    const size_t desc_off = sizeof(esp_image_header_t) + sizeof(esp_image_segment_header_t);
    if (n < desc_off + offsetof(esp_app_desc_t, project_name) + 32) return true;    // need more data
    const esp_image_header_t *ih = (const esp_image_header_t *)d;
    const esp_app_desc_t *ad = (const esp_app_desc_t *)(d + desc_off);
    if (ih->magic != ESP_IMAGE_HEADER_MAGIC || ih->chip_id != ESP_CHIP_ID_ESP32C3) {
        snprintf(err, el, "not an ESP32-C3 application image (upload SerialPill-*-ota.bin)");
        return false;
    }
    if (ad->magic_word != ESP_APP_DESC_MAGIC_WORD || strncmp(ad->project_name, "SerialPill", sizeof ad->project_name)) {
        snprintf(err, el, "image is not SerialPill (project '%.32s'); use 'Restore Shelly' for Shelly firmware",
                 ad->magic_word == ESP_APP_DESC_MAGIC_WORD ? ad->project_name : "?");
        return false;
    }
    return true;
}

esp_err_t ota_begin_upload(size_t size, void **handle, char *err, size_t el)
{
    confirm_running();
    self_ota_t *o = calloc(1, sizeof *o);
    if (!o) return ESP_ERR_NO_MEM;
    o->part = esp_ota_get_next_update_partition(NULL);
    if (!o->part || (size && size > o->part->size)) {
        snprintf(err, el, "image too large for %s", o->part ? o->part->label : "slot");
        free(o);
        return ESP_ERR_INVALID_SIZE;
    }
    esp_err_t e = esp_ota_begin(o->part, size ? size : OTA_SIZE_UNKNOWN, &o->h);
    if (e != ESP_OK) { snprintf(err, el, "ota begin: %s", esp_err_to_name(e)); free(o); return e; }
    *handle = o;
    audit("firmware: SerialPill update started -> %s", o->part->label);
    return ESP_OK;
}

esp_err_t ota_write_chunk(void *handle, const uint8_t *d, size_t n, char *err, size_t el)
{
    self_ota_t *o = handle;
    if (!o->checked) {
        size_t take = n < sizeof o->head - o->headlen ? n : sizeof o->head - o->headlen;
        memcpy(o->head + o->headlen, d, take);
        o->headlen += take;
        if (!check_header(o->head, o->headlen, err, el)) return ESP_ERR_INVALID_ARG;
        if (o->headlen == sizeof o->head) o->checked = true;
    }
    esp_err_t e = esp_ota_write(o->h, d, n);
    if (e != ESP_OK) { snprintf(err, el, "flash write: %s", esp_err_to_name(e)); return e; }
    o->written += n;
    return ESP_OK;
}

esp_err_t ota_finish(void *handle, char *err, size_t el)
{
    self_ota_t *o = handle;
    esp_err_t e = o->checked ? esp_ota_end(o->h) : ESP_ERR_INVALID_SIZE;
    if (e == ESP_OK) e = esp_ota_set_boot_partition(o->part);
    if (e != ESP_OK) {
        snprintf(err, el, "image rejected: %s", esp_err_to_name(e));
        audit("firmware: SerialPill update FAILED (%s)", esp_err_to_name(e));
    } else {
        esp_app_desc_t d;
        esp_ota_get_partition_description(o->part, &d);
        audit("firmware: SerialPill %s installed in %s, rebooting", d.version, o->part->label);
    }
    free(o);
    return e;
}

void ota_abort(void *handle)
{
    self_ota_t *o = handle;
    if (!o) return;
    esp_ota_abort(o->h);
    free(o);
    audit("firmware: SerialPill update aborted");
}

static void confirm_task(void *arg)
{
    // A crash or reset loop before this point makes the bootloader roll back. Network problems
    // must not: rolling back could start the other slot (possibly stock Shelly) under the wrong
    // bootloader. So the image is confirmed after 60 s of stable operation.
    vTaskDelay(pdMS_TO_TICKS(60000));
    esp_ota_mark_app_valid_cancel_rollback();
    audit("firmware: running image confirmed");
    vTaskDelete(NULL);
}

void ota_mark_valid_later(void)
{
    esp_ota_img_states_t st;
    if (esp_ota_get_state_partition(esp_ota_get_running_partition(), &st) == ESP_OK && st == ESP_OTA_IMG_PENDING_VERIFY)
        xTaskCreate(confirm_task, "ota_confirm", 3072, NULL, 3, NULL);
}

// ================================================================ Shelly restore
// The official package writes app_0/fs_0 and a boot state that starts app_0, so SerialPill must
// run from app_1 while restoring. If it runs from app_0 it first copies itself to app_1.

static volatile int s_progress = -1;          // percent, -1 idle
static char s_state[96] = "idle";
static bool s_busy;

int shelly_restore_progress(void) { return s_progress; }
const char *shelly_restore_state(void) { return s_state; }

static void set_state(const char *fmt, const char *arg)
{
    snprintf(s_state, sizeof s_state, fmt, arg);
    ESP_LOGI(TAG, "%s", s_state);
}

esp_err_t shelly_restore_prepare(char *err, size_t el)
{
    const esp_partition_t *run = esp_ota_get_running_partition();
    confirm_running();
    if (strcmp(run->label, "app_1") == 0) return ESP_OK;
    const esp_partition_t *dst = esp_partition_find_first(ESP_PARTITION_TYPE_APP, ESP_PARTITION_SUBTYPE_APP_OTA_1, NULL);
    esp_image_metadata_t md;
    const esp_partition_pos_t pos = { .offset = run->address, .size = run->size };
    if (!dst || esp_image_verify(ESP_IMAGE_VERIFY_SILENT, &pos, &md) != ESP_OK) {
        snprintf(err, el, "cannot read the running image");
        return ESP_FAIL;
    }
    audit("firmware: moving SerialPill to app_1 before Shelly restore (%lu B)", (unsigned long)md.image_len);
    set_state("moving SerialPill to app_1%s", "");
    esp_ota_handle_t h;
    esp_err_t e = esp_ota_begin(dst, md.image_len, &h);
    uint8_t *buf = malloc(4096);
    for (size_t off = 0; e == ESP_OK && off < md.image_len; off += 4096) {
        size_t n = md.image_len - off < 4096 ? md.image_len - off : 4096;
        e = esp_partition_read(run, off, buf, n);
        if (e == ESP_OK) e = esp_ota_write(h, buf, n);
        s_progress = off * 100 / md.image_len;
    }
    free(buf);
    if (e == ESP_OK) e = esp_ota_end(h); else esp_ota_abort(h);
    if (e == ESP_OK) e = esp_ota_set_boot_partition(dst);
    if (e == ESP_OK) {
        // the next boot starts from app_1; confirm it immediately so it is not rolled back
        config_blob_set("restore", "1", 1);
        set_state("SerialPill moved to app_1, rebooting%s", "");
    } else {
        snprintf(err, el, "copy failed: %s", esp_err_to_name(e));
    }
    s_progress = -1;
    return e == ESP_OK ? ESP_ERR_INVALID_STATE : e;    // INVALID_STATE: reboot required
}

typedef enum { Z_HDR, Z_NAME, Z_DATA, Z_DONE } zstate_t;

typedef struct {
    const char *type, *src, *ptn;
    uint32_t addr, size;
    char sha[65];
    bool done;
} part_t;

struct shelly_restore {
    zstate_t st;
    uint8_t hdr[30];
    size_t hdrlen;
    char name[64];
    size_t namelen, need_name, skip_extra;
    size_t remaining;                  // bytes of current entry data left
    // current entry sink
    part_t *cur;
    const esp_partition_t *part;
    size_t part_off;
    uint8_t *ram;                      // manifest / small parts
    size_t ramlen, ramcap;
    mbedtls_sha256_context sha;
    // manifest
    cJSON *manifest;
    part_t parts[8];
    int nparts;
    uint8_t *boot, *otadata;           // buffered critical parts
    char fs_label[17];                 // partition that received the Shelly filesystem
    size_t boot_len, otadata_len;
    size_t total, fed;
};

shelly_restore_t *shelly_restore_begin(char *err, size_t el)
{
    if (strcmp(esp_ota_get_running_partition()->label, "app_1") != 0) {
        snprintf(err, el, "SerialPill must run from app_1 (use prepare first)");
        return NULL;
    }
    shelly_restore_t *r = calloc(1, sizeof *r);
    if (!r) snprintf(err, el, "out of memory");
    return r;
}

static esp_err_t parse_manifest(shelly_restore_t *r, char *err, size_t el)
{
    r->manifest = cJSON_ParseWithLength((const char *)r->ram, r->ramlen);
    const cJSON *m = r->manifest;
    const cJSON *name = cJSON_GetObjectItem(m, "name"), *plat = cJSON_GetObjectItem(m, "platform");
    if (!cJSON_IsString(name) || strcmp(name->valuestring, "Pill") || !cJSON_IsString(plat) || strcmp(plat->valuestring, "esp32c3")) {
        snprintf(err, el, "not an official Shelly Pill package");
        return ESP_ERR_INVALID_ARG;
    }
    const cJSON *p;
    cJSON_ArrayForEach(p, cJSON_GetObjectItem(m, "parts")) {
        if (r->nparts >= 8) break;
        part_t *pt = &r->parts[r->nparts++];
        const cJSON *v;
        pt->type = cJSON_GetStringValue(cJSON_GetObjectItem(p, "type"));
        pt->src = cJSON_GetStringValue(cJSON_GetObjectItem(p, "src"));
        pt->ptn = cJSON_GetStringValue(cJSON_GetObjectItem(p, "ptn"));
        if ((v = cJSON_GetObjectItem(p, "addr"))) pt->addr = v->valuedouble;
        if ((v = cJSON_GetObjectItem(p, "size"))) pt->size = v->valuedouble;
        const char *sha = cJSON_GetStringValue(cJSON_GetObjectItem(p, "cs_sha256"));
        if (sha) snprintf(pt->sha, sizeof pt->sha, "%s", sha);
        if (!pt->type) { snprintf(err, el, "manifest part without type"); return ESP_ERR_INVALID_ARG; }
        if (pt->src && strlen(pt->sha) != 64) { snprintf(err, el, "part %s has no SHA-256", pt->src); return ESP_ERR_INVALID_ARG; }
        r->total += pt->size;
    }
    const char *ver = cJSON_GetStringValue(cJSON_GetObjectItem(m, "version"));
    audit("firmware: restoring Shelly %s", ver ? ver : "?");
    return ESP_OK;
}

static esp_err_t start_entry(shelly_restore_t *r, char *err, size_t el)
{
    r->cur = NULL;
    r->part = NULL;
    r->ramlen = 0;
    if (strcmp(r->name, "manifest.json") == 0) {
        if (r->remaining > 16384) { snprintf(err, el, "manifest too large"); return ESP_ERR_INVALID_SIZE; }
        r->ramcap = r->remaining;
        r->ram = realloc(r->ram, r->ramcap + 1);
        return r->ram ? ESP_OK : ESP_ERR_NO_MEM;
    }
    if (!r->manifest) { snprintf(err, el, "manifest.json must be the first file"); return ESP_ERR_INVALID_ARG; }
    for (int i = 0; i < r->nparts; i++)
        if (r->parts[i].src && strcmp(r->parts[i].src, r->name) == 0) r->cur = &r->parts[i];
    if (!r->cur) return ESP_OK;                         // not referenced by the manifest: skip
    part_t *p = r->cur;
    if (p->size != r->remaining) { snprintf(err, el, "%s: size mismatch", p->src); return ESP_ERR_INVALID_SIZE; }
    mbedtls_sha256_init(&r->sha);
    mbedtls_sha256_starts(&r->sha, 0);
    if (!strcmp(p->type, "boot") || !strcmp(p->type, "pt") || !strcmp(p->type, "otadata")) {
        if (p->size > 0x10000) { snprintf(err, el, "%s too large", p->src); return ESP_ERR_INVALID_SIZE; }
        r->ramcap = p->size;
        r->ram = realloc(r->ram, r->ramcap + 1);
        return r->ram ? ESP_OK : ESP_ERR_NO_MEM;
    }
    if (!strcmp(p->type, "app") || !strcmp(p->type, "fs")) {
        r->part = p->ptn ? esp_partition_find_first(ESP_PARTITION_TYPE_ANY, ESP_PARTITION_SUBTYPE_ANY, p->ptn) : NULL;
        if (!r->part || p->size > r->part->size) { snprintf(err, el, "%s: bad target partition", p->src); return ESP_ERR_INVALID_ARG; }
        if (r->part == esp_ota_get_running_partition()) { snprintf(err, el, "refusing to overwrite the running firmware"); return ESP_ERR_INVALID_STATE; }
        r->part_off = 0;
        set_state("writing %s", p->ptn);
        return esp_partition_erase_range(r->part, 0, (p->size + 0xFFF) & ~0xFFF);
    }
    snprintf(err, el, "unsupported part type %s", p->type);
    return ESP_ERR_NOT_SUPPORTED;
}

static esp_err_t entry_data(shelly_restore_t *r, const uint8_t *d, size_t n)
{
    if (!r->cur) {
        if (r->ram && !r->manifest && r->ramcap) { memcpy(r->ram + r->ramlen, d, n); r->ramlen += n; }   // manifest
        return ESP_OK;
    }
    mbedtls_sha256_update(&r->sha, d, n);
    if (r->part) {
        esp_err_t e = esp_partition_write(r->part, r->part_off, d, n);
        r->part_off += n;
        return e;
    }
    memcpy(r->ram + r->ramlen, d, n);
    r->ramlen += n;
    return ESP_OK;
}

static esp_err_t end_entry(shelly_restore_t *r, char *err, size_t el)
{
    if (!r->manifest && r->ramcap && !r->cur && strcmp(r->name, "manifest.json") == 0) {
        r->ram[r->ramlen] = 0;
        esp_err_t e = parse_manifest(r, err, el);
        r->ramcap = 0;
        return e;
    }
    part_t *p = r->cur;
    if (!p) return ESP_OK;
    uint8_t h[32];
    char hex[65];
    mbedtls_sha256_finish(&r->sha, h);
    mbedtls_sha256_free(&r->sha);
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", h[i]);
    if (strcasecmp(hex, p->sha)) { snprintf(err, el, "%s: SHA-256 mismatch", p->src); return ESP_ERR_INVALID_CRC; }
    if (!strcmp(p->type, "pt")) {
        // Only the identical layout is supported (the table is never rewritten). Compare entries by
        // meaning - type, subtype, offset, size, label - so a table generated by esptool/PlatformIO
        // (no flags, own MD5 record) matches the Shelly one; the package file has extra copies after
        // the table, which are ignored.
        uint8_t *cur = malloc(0xC00);
        bool same = cur && esp_flash_read(NULL, cur, p->addr, 0xC00) == ESP_OK;
        for (size_t o = 0; same && o + 32 <= 0xC00; o += 32) {
            const uint8_t *a = r->ram + o, *b = cur + o;
            bool ea = a[0] == 0xAA && a[1] == 0x50, eb = b[0] == 0xAA && b[1] == 0x50;
            if (ea != eb) same = false;
            else if (!ea) break;                                       // end of both tables
            else if (memcmp(a + 2, b + 2, 10) || memcmp(a + 12, b + 12, 16)) same = false;
        }
        free(cur);
        if (!same) { snprintf(err, el, "package uses a different partition table"); return ESP_ERR_NOT_SUPPORTED; }
    } else if (!strcmp(p->type, "boot")) {
        r->boot = r->ram; r->boot_len = r->ramlen; r->ram = NULL; r->ramcap = 0;
    } else if (!strcmp(p->type, "otadata")) {
        r->otadata = r->ram; r->otadata_len = r->ramlen; r->ram = NULL; r->ramcap = 0;
    } else if (!strcmp(p->type, "fs") && p->ptn) {
        snprintf(r->fs_label, sizeof r->fs_label, "%s", p->ptn);
    }
    p->done = true;
    return ESP_OK;
}

esp_err_t shelly_restore_feed(shelly_restore_t *r, const uint8_t *d, size_t n, char *err, size_t el)
{
    esp_err_t e = ESP_OK;
    r->fed += n;
    if (r->total) s_progress = r->fed * 100 / (r->total + 4096);
    while (n && e == ESP_OK) {
        switch (r->st) {
            case Z_HDR: {
                size_t take = 30 - r->hdrlen < n ? 30 - r->hdrlen : n;
                memcpy(r->hdr + r->hdrlen, d, take);
                r->hdrlen += take; d += take; n -= take;
                if (r->hdrlen < 4) break;
                uint32_t sig = r->hdr[0] | r->hdr[1] << 8 | r->hdr[2] << 16 | (uint32_t)r->hdr[3] << 24;
                if (sig == 0x02014b50 || sig == 0x06054b50) { r->st = Z_DONE; break; }    // central directory
                if (sig != 0x04034b50) { snprintf(err, el, "not a zip file"); return ESP_ERR_INVALID_ARG; }
                if (r->hdrlen < 30) break;
                uint16_t flags = r->hdr[6] | r->hdr[7] << 8, method = r->hdr[8] | r->hdr[9] << 8;
                uint32_t csize = r->hdr[18] | r->hdr[19] << 8 | r->hdr[20] << 16 | (uint32_t)r->hdr[21] << 24;
                r->need_name = r->hdr[26] | r->hdr[27] << 8;
                r->skip_extra = r->hdr[28] | r->hdr[29] << 8;
                if (method != 0 || (flags & 0x08)) { snprintf(err, el, "compressed zip not supported (use the official package)"); return ESP_ERR_NOT_SUPPORTED; }
                if (r->need_name >= sizeof r->name) { snprintf(err, el, "file name too long"); return ESP_ERR_INVALID_ARG; }
                r->remaining = csize;
                r->namelen = 0;
                r->st = Z_NAME;
                break;
            }
            case Z_NAME: {
                size_t want = r->need_name - r->namelen;
                size_t take = want < n ? want : n;
                memcpy(r->name + r->namelen, d, take);
                r->namelen += take; d += take; n -= take;
                if (r->namelen < r->need_name) break;
                r->name[r->namelen] = 0;
                if (r->skip_extra) {
                    size_t s = r->skip_extra < n ? r->skip_extra : n;
                    r->skip_extra -= s; d += s; n -= s;
                    if (r->skip_extra) break;
                }
                e = start_entry(r, err, el);
                r->st = Z_DATA;
                if (e == ESP_OK && r->remaining == 0) { e = end_entry(r, err, el); r->st = Z_HDR; r->hdrlen = 0; }
                break;
            }
            case Z_DATA: {
                size_t take = r->remaining < n ? r->remaining : n;
                e = entry_data(r, d, take);
                if (e != ESP_OK) snprintf(err, el, "flash write failed: %s", esp_err_to_name(e));
                r->remaining -= take; d += take; n -= take;
                if (e == ESP_OK && r->remaining == 0) { e = end_entry(r, err, el); r->st = Z_HDR; r->hdrlen = 0; }
                break;
            }
            case Z_DONE:
                n = 0;
                break;
        }
    }
    return e;
}

// The official fs.img is a factory configuration: without WiFi settings the restored Shelly would
// open its own AP and disappear from the network. Write the current client settings into its user
// configuration (conf9.json). Both firmwares use LittleFS disk version 2.1. Failure is not fatal.
static void carry_wifi_to_shelly(const char *label)
{
    if (!label[0] || !g_cfg.wifi_sta || !g_cfg.wifi_ssid[0]) return;
    esp_vfs_littlefs_conf_t lc = { .base_path = "/shellyfs", .partition_label = label };
    if (esp_vfs_littlefs_register(&lc) != ESP_OK) {
        audit("firmware: cannot mount Shelly filesystem, Shelly starts with factory WiFi (own AP)");
        return;
    }
    cJSON *j = cJSON_CreateObject();
    cJSON *wifi = cJSON_AddObjectToObject(j, "wifi");
    cJSON_AddBoolToObject(cJSON_AddObjectToObject(wifi, "ap"), "enable", false);
    cJSON *sta = cJSON_AddObjectToObject(wifi, "sta");
    cJSON_AddBoolToObject(sta, "enable", true);
    cJSON_AddStringToObject(sta, "ssid", g_cfg.wifi_ssid);
    cJSON_AddStringToObject(sta, "pass", g_cfg.wifi_pass);
    if (g_cfg.static_ip) {
        cJSON_AddStringToObject(sta, "ipv4mode", "static");
        cJSON_AddStringToObject(sta, "ip", g_cfg.ip);
        cJSON_AddStringToObject(sta, "netmask", g_cfg.mask);
        if (g_cfg.gw[0]) cJSON_AddStringToObject(sta, "gw", g_cfg.gw);
        if (g_cfg.dns[0]) cJSON_AddStringToObject(sta, "nameserver", g_cfg.dns);
    }
    char *txt = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    FILE *f = txt ? fopen("/shellyfs/conf9.json", "w") : NULL;
    bool ok = f && fputs(txt, f) >= 0;
    if (f) ok = (fclose(f) == 0) && ok;
    if (txt) { memset(txt, 0, strlen(txt)); free(txt); }
    esp_vfs_littlefs_unregister(label);
    if (ok) audit("firmware: WiFi '%s' carried over to the Shelly configuration", g_cfg.wifi_ssid);
    else audit("firmware: could not write the Shelly WiFi configuration");
}

esp_err_t shelly_restore_finish(shelly_restore_t *r, char *err, size_t el)
{
    if (!r->manifest) { snprintf(err, el, "manifest missing"); return ESP_ERR_INVALID_ARG; }
    for (int i = 0; i < r->nparts; i++) {
        if (r->parts[i].src && !r->parts[i].done) { snprintf(err, el, "package incomplete: %s missing", r->parts[i].src); return ESP_ERR_INVALID_SIZE; }
    }
    if (!r->boot || !r->otadata || r->boot[0] != 0xE9) { snprintf(err, el, "package lacks bootloader/boot state"); return ESP_ERR_INVALID_ARG; }
    const esp_partition_t *otadata = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, NULL);
    const esp_partition_t *nvs = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_NVS, NULL);
    if (!otadata || r->otadata_len > otadata->size) { snprintf(err, el, "boot state does not fit"); return ESP_ERR_INVALID_SIZE; }

    carry_wifi_to_shelly(r->fs_label);

    // Point of no return. Order: Shelly boot state first (the ESP-IDF bootloader treats it as
    // invalid otadata and would boot app_0 = Shelly), then the Shelly bootloader.
    audit("firmware: all Shelly parts verified, writing boot state and bootloader");
    set_state("writing boot state and bootloader%s", "");
    esp_err_t e = esp_partition_erase_range(otadata, 0, otadata->size);
    if (e == ESP_OK) e = esp_partition_write(otadata, 0, r->otadata, r->otadata_len);
    size_t bl = (r->boot_len + 0xFFF) & ~0xFFF;
    if (e == ESP_OK) e = esp_flash_erase_region(NULL, 0, bl);
    if (e == ESP_OK) e = esp_flash_write(NULL, r->boot, 0, r->boot_len);
    if (e != ESP_OK) {
        snprintf(err, el, "boot region write failed: %s (recover over USB-C with esptool)", esp_err_to_name(e));
        audit("firmware: %s", err);
        return e;
    }
    // SerialPill configuration is not meant for Shelly: wipe NVS like the official package does
    if (nvs) esp_partition_erase_range(nvs, 0, nvs->size);
    set_state("Shelly firmware restored, rebooting%s", "");
    audit("firmware: Shelly firmware restored, rebooting into Shelly");
    s_progress = 100;
    return ESP_OK;
}

void shelly_restore_abort(shelly_restore_t *r)
{
    if (!r) return;
    cJSON_Delete(r->manifest);
    free(r->ram);
    free(r->boot);
    free(r->otadata);
    free(r);
    s_progress = -1;
}

// ---------------------------------------------------------------- download from Shelly servers
extern const char shelly_ca_pem_start[] asm("_binary_shelly_ca_pem_start");

#define UPDATE_INDEX "https://updates.shelly.cloud/update/Pill"

static esp_http_client_handle_t open_url(const char *url, bool shelly_ca)
{
    esp_http_client_config_t c = { .url = url, .timeout_ms = 30000, .buffer_size = 2048, .keep_alive_enable = false };
    if (shelly_ca) c.cert_pem = shelly_ca_pem_start;
    else c.crt_bundle_attach = esp_crt_bundle_attach;
    esp_http_client_handle_t h = esp_http_client_init(&c);
    if (h && esp_http_client_open(h, 0) == ESP_OK && esp_http_client_fetch_headers(h) >= 0 &&
        esp_http_client_get_status_code(h) == 200) return h;
    if (h) { esp_http_client_close(h); esp_http_client_cleanup(h); }
    return NULL;
}

static esp_http_client_handle_t open_any(const char *url)
{
    esp_http_client_handle_t h = open_url(url, true);   // Shelly's own CA (update server)
    return h ? h : open_url(url, false);                // public CAs (CDN)
}

esp_err_t shelly_check_server(cJSON **out, char *err, size_t el)
{
    esp_http_client_handle_t h = open_any(UPDATE_INDEX);
    if (!h) { snprintf(err, el, "cannot reach %s", UPDATE_INDEX); return ESP_FAIL; }
    char *buf = calloc(1, 2049);
    int n = 0, r;
    while (buf && n < 2048 && (r = esp_http_client_read(h, buf + n, 2048 - n)) > 0) n += r;
    esp_http_client_close(h);
    esp_http_client_cleanup(h);
    *out = buf ? cJSON_Parse(buf) : NULL;
    free(buf);
    if (!*out) { snprintf(err, el, "invalid update index"); return ESP_FAIL; }
    return ESP_OK;
}

// One download attempt: streams and verifies the whole package into app_0/fs_0 and buffers the boot
// parts. Nothing outside app_0/fs_0 is written, so a failed attempt can simply be repeated.
// *retry is set when the failure was a transfer problem (worth another attempt).
static shelly_restore_t *download_once(const char *url, const char *want, bool *retry, char *err, size_t el)
{
    *retry = false;
    esp_http_client_handle_t h = open_any(url);
    if (!h) { snprintf(err, el, "download failed"); *retry = true; return NULL; }
    shelly_restore_t *r = shelly_restore_begin(err, el);
    uint8_t *buf = malloc(4096);
    mbedtls_sha256_context sc;
    mbedtls_sha256_init(&sc);
    mbedtls_sha256_starts(&sc, 0);
    int n = 0;
    bool ok = r && buf;
    while (ok && (n = esp_http_client_read(h, (char *)buf, 4096)) > 0) {
        mbedtls_sha256_update(&sc, buf, n);
        if (shelly_restore_feed(r, buf, n, err, el) != ESP_OK) ok = false;
    }
    uint8_t hash[32];
    char hex[65];
    mbedtls_sha256_finish(&sc, hash);
    mbedtls_sha256_free(&sc);
    for (int i = 0; i < 32; i++) sprintf(hex + 2 * i, "%02x", hash[i]);
    if (ok && (n < 0 || !esp_http_client_is_complete_data_received(h))) {
        snprintf(err, el, "download interrupted (%d)", n);
        ok = false;
        *retry = true;
    }
    if (ok && want[0] && strcasecmp(want, hex)) {
        snprintf(err, el, "package SHA-256 does not match the server index");
        ok = false;
    }
    free(buf);
    esp_http_client_close(h);
    esp_http_client_cleanup(h);
    if (!ok) { shelly_restore_abort(r); return NULL; }
    return r;
}

static void restore_task(void *arg)
{
    char *channel = arg, err[128] = "";
    cJSON *idx = NULL;
    shelly_restore_t *r = NULL;
    set_state("checking Shelly update server%s", "");
    s_progress = 0;
    if (shelly_check_server(&idx, err, sizeof err) != ESP_OK) goto fail;
    const char *url = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(idx, channel), "url"));
    const char *ver = cJSON_GetStringValue(cJSON_GetObjectItem(cJSON_GetObjectItem(idx, channel), "version"));
    if (!url) { snprintf(err, sizeof err, "no %s firmware on the server", channel); goto fail; }
    // the CDN path ends with the SHA-256 of the package: verify the whole file against it too
    const char *slash = strrchr(url, '/');
    char want[65] = "";
    if (slash && strlen(slash + 1) == 64) snprintf(want, sizeof want, "%s", slash + 1);
    for (int attempt = 1; attempt <= 3 && !r; attempt++) {
        bool retry;
        audit("firmware: downloading Shelly %s (%s), attempt %d", ver ? ver : "?", channel, attempt);
        r = download_once(url, want, &retry, err, sizeof err);
        if (!r && !retry) goto fail;
        if (!r) { audit("firmware: %s, retrying", err); vTaskDelay(pdMS_TO_TICKS(3000)); }
    }
    if (!r) goto fail;
    if (shelly_restore_finish(r, err, sizeof err) != ESP_OK) goto fail;
    shelly_restore_abort(r);
    s_progress = 100;
    sys_reboot_later(2000);
    goto out;
fail:
    set_state("failed: %s", err);
    audit("firmware: Shelly restore failed: %s", err);
    shelly_restore_abort(r);
    s_progress = -1;
out:
    cJSON_Delete(idx);
    free(channel);
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t shelly_restore_from_server(const char *channel, char *err, size_t el)
{
    if (s_busy) { snprintf(err, el, "restore already running"); return ESP_ERR_INVALID_STATE; }
    if (strcmp(channel, "stable") && strcmp(channel, "beta")) { snprintf(err, el, "channel must be stable or beta"); return ESP_ERR_INVALID_ARG; }
    esp_err_t e = shelly_restore_prepare(err, el);
    if (e == ESP_ERR_INVALID_STATE) {
        // reboot into app_1 and continue automatically
        char c[16];
        snprintf(c, sizeof c, "srv:%s", channel);
        config_blob_set("restore", c, strlen(c));
        sys_reboot_later(1500);
        return ESP_ERR_INVALID_STATE;
    }
    if (e != ESP_OK) return e;
    s_busy = true;
    if (xTaskCreate(restore_task, "restore", 8192, strdup(channel), 4, NULL) != pdPASS) {
        s_busy = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

// called at boot: continue a restore that required moving to app_1 first
void shelly_restore_resume(void)
{
    void *d; size_t n;
    if (config_blob_get("restore", &d, &n) != ESP_OK) return;
    config_blob_erase("restore");
    esp_ota_mark_app_valid_cancel_rollback();
    if (n > 4 && (strncmp(d, "srv:", 4) == 0 || strncmp(d, "url:", 4) == 0)) {
        char err[96];
        for (int i = 0; i < 60 && !wifi_connected(); i++) vTaskDelay(pdMS_TO_TICKS(1000));
        esp_err_t e = strncmp(d, "srv:", 4) == 0 ? shelly_restore_from_server((char *)d + 4, err, sizeof err)
                                                 : firmware_from_url((char *)d + 4, err, sizeof err);
        if (e != ESP_OK) audit("firmware: resume restore failed: %s", err);
    } else {
        set_state("ready: upload the official Shelly package%s", "");
    }
    free(d);
}

// ---------------------------------------------------------------- update from a link
// The first bytes decide what the file is: an ESP32 application image (0xE9) is installed as a
// SerialPill update, a zip ("PK") is treated as an official Shelly package and restored.
static void url_task(void *arg)
{
    char *url = arg, err[128] = "";
    esp_http_client_handle_t h = NULL;
    shelly_restore_t *r = NULL;
    void *ota = NULL;
    uint8_t *buf = malloc(4096);
    set_state("downloading %s", url);
    s_progress = 0;
    if (!buf || !(h = open_any(url))) { snprintf(err, sizeof err, "cannot download %s", url); goto fail; }
    int64_t total = esp_http_client_get_content_length(h), got = 0;
    int n = esp_http_client_read(h, (char *)buf, 4096);
    if (n < 4) { snprintf(err, sizeof err, "file too short"); goto fail; }
    bool zip = buf[0] == 'P' && buf[1] == 'K' && buf[2] == 3 && buf[3] == 4;
    if (!zip && buf[0] != ESP_IMAGE_HEADER_MAGIC) { snprintf(err, sizeof err, "neither a SerialPill image nor a Shelly package"); goto fail; }
    if (zip) {
        esp_err_t e = shelly_restore_prepare(err, sizeof err);
        if (e == ESP_ERR_INVALID_STATE) {           // moved to app_1: reboot and download again
            size_t l = strlen(url) + 5;
            char *rec = malloc(l);
            if (rec) { snprintf(rec, l, "url:%s", url); config_blob_set("restore", rec, strlen(rec)); free(rec); }
            set_state("SerialPill moved to app_1, rebooting%s", "");
            sys_reboot_later(1500);
            goto out;
        }
        if (e != ESP_OK || !(r = shelly_restore_begin(err, sizeof err))) goto fail;
        audit("firmware: Shelly package from %s", url);
    } else {
        if (ota_begin_upload(total > 0 ? (size_t)total : 0, &ota, err, sizeof err) != ESP_OK) goto fail;
        audit("firmware: SerialPill image from %s", url);
    }
    set_state(zip ? "writing Shelly firmware%s" : "installing SerialPill update%s", "");
    do {
        esp_err_t e = zip ? shelly_restore_feed(r, buf, n, err, sizeof err) : ota_write_chunk(ota, buf, n, err, sizeof err);
        if (e != ESP_OK) goto fail;
        got += n;
        if (total > 0) s_progress = got * 100 / total;
    } while ((n = esp_http_client_read(h, (char *)buf, 4096)) > 0);
    if (n < 0 || !esp_http_client_is_complete_data_received(h)) { snprintf(err, sizeof err, "download interrupted"); goto fail; }
    if (zip) {
        if (shelly_restore_finish(r, err, sizeof err) != ESP_OK) goto fail;
    } else {
        void *o = ota;
        ota = NULL;
        if (ota_finish(o, err, sizeof err) != ESP_OK) goto fail;
        set_state("SerialPill updated, rebooting%s", "");
    }
    s_progress = 100;
    sys_reboot_later(2000);
    goto out;
fail:
    set_state("failed: %s", err);
    audit("firmware: update from link failed: %s", err);
    s_progress = -1;
out:
    if (ota) ota_abort(ota);
    shelly_restore_abort(r);
    if (h) { esp_http_client_close(h); esp_http_client_cleanup(h); }
    free(buf);
    free(url);
    s_busy = false;
    vTaskDelete(NULL);
}

esp_err_t firmware_from_url(const char *url, char *err, size_t el)
{
    if (s_busy) { snprintf(err, el, "another firmware operation is running"); return ESP_ERR_INVALID_STATE; }
    if (strncmp(url, "http://", 7) && strncmp(url, "https://", 8)) { snprintf(err, el, "link must start with http:// or https://"); return ESP_ERR_INVALID_ARG; }
    if (strlen(url) > 400) { snprintf(err, el, "link too long"); return ESP_ERR_INVALID_ARG; }
    s_busy = true;
    if (xTaskCreate(url_task, "fw_url", 8192, strdup(url), 4, NULL) != pdPASS) {
        s_busy = false;
        snprintf(err, el, "out of memory");
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}
