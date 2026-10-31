// First boot after installation through the stock Shelly updater.
//
// The Shelly bootloader keeps its own boot state in the otadata partition and rolls back to the
// Shelly firmware after a few boots unless the new image "commits". SerialPill therefore replaces
// the Shelly bootloader with a standard ESP-IDF bootloader built for the identical partition table
// (offset 0x10000) and writes standard otadata selecting the running slot. Partition table, NVS
// calibration data and the `shelly` factory partition are left untouched.
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_flash.h"
#include "esp_partition.h"
#include "esp_ota_ops.h"
#include "esp_littlefs.h"
#include "esp_rom_crc.h"
#include "app.h"

static const char *TAG = "migrate";

extern const uint8_t std_bl_start[] asm("_binary_bootloader_std_bin_start");
extern const uint8_t std_bl_end[]   asm("_binary_bootloader_std_bin_end");

#define BL_ADDR      0x0
#define BL_REGION    0x10000            // bootloader may use everything below the partition table

static bool flash_equals(uint32_t addr, const uint8_t *data, size_t len)
{
    uint8_t buf[256];
    for (size_t off = 0; off < len; off += sizeof buf) {
        size_t n = len - off < sizeof buf ? len - off : sizeof buf;
        if (esp_flash_read(NULL, buf, addr + off, n) != ESP_OK || memcmp(buf, data + off, n)) return false;
    }
    return true;
}

static esp_err_t write_bootloader(const uint8_t *bl, size_t len)
{
    size_t erase = (len + 0xFFF) & ~0xFFF;
    if (erase > BL_REGION) return ESP_ERR_INVALID_SIZE;
    for (int attempt = 0; attempt < 3; attempt++) {
        esp_err_t e = esp_flash_erase_region(NULL, BL_ADDR, erase);
        if (e == ESP_OK) e = esp_flash_write(NULL, bl, BL_ADDR, len);
        if (e == ESP_OK && flash_equals(BL_ADDR, bl, len)) return ESP_OK;
        ESP_LOGE(TAG, "bootloader write attempt %d failed: %s", attempt + 1, esp_err_to_name(e));
    }
    return ESP_FAIL;
}

// Pull WiFi settings (and an admin password hash, if Shelly auth was enabled) from the Shelly
// configuration of the slot the stock firmware ran from.
static void find_ha1(const cJSON *o, char *realm, char *ha1)
{
    if (!cJSON_IsObject(o) || ha1[0]) return;
    const cJSON *h = cJSON_GetObjectItem(o, "ha1"), *r = cJSON_GetObjectItem(o, "realm");
    if (cJSON_IsString(h) && strlen(h->valuestring) == 64 && cJSON_IsString(r)) {
        snprintf(realm, 65, "%s", r->valuestring);
        snprintf(ha1, 65, "%s", h->valuestring);
        return;
    }
    const cJSON *c;
    cJSON_ArrayForEach(c, o) find_ha1(c, realm, ha1);
}

static bool import_from(const char *label)
{
    esp_vfs_littlefs_conf_t lc = { .base_path = "/shelly", .partition_label = label, .read_only = true };
    if (esp_vfs_littlefs_register(&lc) != ESP_OK) return false;
    bool ok = false;
    FILE *f = fopen("/shelly/conf9.json", "r");
    if (f) {
        char *buf = calloc(1, 4096);
        size_t n = buf ? fread(buf, 1, 4095, f) : 0;
        fclose(f);
        cJSON *j = n ? cJSON_Parse(buf) : NULL;
        const cJSON *sta = cJSON_GetObjectItem(cJSON_GetObjectItem(j, "wifi"), "sta");
        const cJSON *ssid = cJSON_GetObjectItem(sta, "ssid"), *pass = cJSON_GetObjectItem(sta, "pass");
        if (cJSON_IsString(ssid) && ssid->valuestring[0] && strlen(ssid->valuestring) < sizeof g_cfg.wifi_ssid) {
            snprintf(g_cfg.wifi_ssid, sizeof g_cfg.wifi_ssid, "%s", ssid->valuestring);
            if (cJSON_IsString(pass) && strlen(pass->valuestring) < sizeof g_cfg.wifi_pass)
                snprintf(g_cfg.wifi_pass, sizeof g_cfg.wifi_pass, "%s", pass->valuestring);
            g_cfg.wifi_sta = true;      // stay on the network the Shelly firmware was using
            ok = true;
        }
        char realm[65] = "", ha1[65] = "";
        find_ha1(j, realm, ha1);
        if (ha1[0] && users_import_shelly_ha1(realm, ha1) == ESP_OK)
            audit("migrate: imported Shelly admin password (user 'admin')");
        cJSON_Delete(j);
        if (buf) memset(buf, 0, 4096);
        free(buf);
    }
    esp_vfs_littlefs_unregister(label);
    return ok;
}

void migrate_import_shelly_config(void)
{
    if (g_cfg.wifi_ssid[0]) return;
    const esp_partition_t *run = esp_ota_get_running_partition();
    // the stock firmware ran from the other slot; its fs carries the live configuration
    const char *first = strcmp(run->label, "app_0") == 0 ? "fs_1" : "fs_0";
    const char *second = strcmp(first, "fs_1") == 0 ? "fs_0" : "fs_1";
    if (import_from(first) || import_from(second)) {
        audit("migrate: WiFi settings imported from Shelly configuration (SSID '%s')", g_cfg.wifi_ssid);
        config_save();
    }
}

esp_err_t migrate_from_shelly(void)
{
    size_t len = std_bl_end - std_bl_start;
    if (len < 1024 || std_bl_start[0] != 0xE9) {
        ESP_LOGE(TAG, "embedded bootloader missing");
        return ESP_ERR_INVALID_STATE;
    }
    if (flash_equals(BL_ADDR, std_bl_start, len)) return ESP_OK;      // already migrated

    const esp_partition_t *run = esp_ota_get_running_partition();
    const esp_partition_t *otadata = esp_partition_find_first(ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_OTA, NULL);
    if (!otadata) return ESP_ERR_NOT_FOUND;
    ESP_LOGW(TAG, "Shelly bootloader detected, migrating (running from %s)", run->label);

    // read the Shelly configuration first; nothing below depends on it
    migrate_import_shelly_config();

    // 1) bootloader. With Shelly boot state still in otadata the ESP-IDF bootloader treats otadata
    //    as invalid and boots ota_0, so a power cut between 1) and 2) still boots a firmware.
    esp_err_t e = write_bootloader(std_bl_start, len);
    if (e != ESP_OK) return e;
    // 2) standard otadata selecting the running slot
    e = esp_partition_erase_range(otadata, 0, otadata->size);
    if (e == ESP_OK) e = esp_ota_set_boot_partition(run);
    if (e != ESP_OK) {
        ESP_LOGE(TAG, "otadata update failed: %s", esp_err_to_name(e));
        return e;
    }
    // 3) The other slot still holds the Shelly application, which cannot start under the ESP-IDF
    //    bootloader. If SerialPill were ever rolled back to it, the device would boot-loop, so its
    //    image header is erased: a rollback then has no target and SerialPill keeps running.
    //    "Restore Shelly" writes a complete official image again.
    migrate_guard_other_slot();
    audit("migrate: replaced Shelly bootloader, SerialPill boots from %s", run->label);
    return ESP_OK;
}

// Runs on every boot (also after a USB install, where no migration happens): the other OTA slot must
// never hold a bootable non-SerialPill image, because the ESP-IDF bootloader would roll back into it
// (stock Shelly cannot start under this bootloader and would boot-loop).
void migrate_guard_other_slot(void)
{
    // Only under the standard bootloader: while the Shelly bootloader is still in place (failed
    // migration) its own rollback needs the Shelly image.
    size_t len = std_bl_end - std_bl_start;
    if (len < 1024 || !flash_equals(BL_ADDR, std_bl_start, len)) return;
    const esp_partition_t *other = esp_ota_get_next_update_partition(NULL);
    esp_app_desc_t d;
    if (!other || esp_ota_get_partition_description(other, &d) != ESP_OK) return;   // empty/invalid already
    if (strncmp(d.project_name, "SerialPill", sizeof d.project_name) == 0) return;
    if (esp_partition_erase_range(other, 0, 0x1000) == ESP_OK)
        audit("migrate: '%.32s' image in %s invalidated (use 'Restore Shelly' to go back)", d.project_name, other->label);
}
