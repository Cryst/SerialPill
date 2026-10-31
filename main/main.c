// SerialPill - wireless UART console server for The Pill by Shelly
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/timers.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_system.h"
#include "esp_app_desc.h"
#include "esp_sntp.h"
#include "app.h"

static const char *TAG = "main";
static char s_dev_id[32];

#define PIN_LED      8      // active low
#define PIN_BUTTON   10     // active low, "reset" button on the PCB

void shelly_restore_resume(void);

const char *sys_version(void) { return esp_app_get_description()->version; }
const char *sys_device_id(void) { return s_dev_id; }

static void reboot_cb(TimerHandle_t t) { esp_restart(); }

void sys_reboot_later(uint32_t ms)
{
    TimerHandle_t t = xTimerCreate("reboot", pdMS_TO_TICKS(ms), pdFALSE, NULL, reboot_cb);
    if (!t || xTimerStart(t, 0) != pdPASS) esp_restart();
}

// LED: blinking = no WiFi, on = connected. Button held 10 s = factory reset (SSH host key kept).
static void io_task(void *arg)
{
    gpio_reset_pin(PIN_LED);
    gpio_set_direction(PIN_LED, GPIO_MODE_OUTPUT);
    gpio_reset_pin(PIN_BUTTON);
    gpio_set_direction(PIN_BUTTON, GPIO_MODE_INPUT);
    gpio_pullup_en(PIN_BUTTON);
    int held = 0;
    for (int i = 0;; i++) {
        bool on = wifi_connected() || (i & 4);
        if (held) on = (i & 1);                 // fast blink while the button is held
        gpio_set_level(PIN_LED, !on);
        if (gpio_get_level(PIN_BUTTON) == 0) {
            if (++held == 100) {                // 100 x 100 ms
                audit("system: factory reset by button");
                void *key = NULL;
                size_t kl = 0;
                config_blob_get("hostkey", &key, &kl);
                config_factory_reset();
                if (key) config_blob_set("hostkey", key, kl);
                esp_restart();
            }
        } else {
            held = 0;
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
}

void time_apply(void)
{
    static char server[64];
    setenv("TZ", g_cfg.tz, 1);
    tzset();
    if (esp_sntp_enabled()) esp_sntp_stop();
    snprintf(server, sizeof server, "%s", g_cfg.ntp_server);     // lwIP keeps the pointer
    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, server);
    esp_sntp_init();
}

static void late_task(void *arg)
{
    shelly_restore_resume();
    vTaskDelete(NULL);
}

void app_main(void)
{
    uint8_t mac[6];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(s_dev_id, sizeof s_dev_id, "serialpill-%02x%02x%02x%02x%02x%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    ESP_LOGI(TAG, "%s %s", s_dev_id, sys_version());

    audit_init();
    ESP_ERROR_CHECK(config_init());
    users_init();
    esp_err_t e = migrate_from_shelly();
    if (e != ESP_OK) ESP_LOGE(TAG, "migration failed: %s", esp_err_to_name(e));
    migrate_import_shelly_config();        // no-op once WiFi is configured
    migrate_guard_other_slot();

    ESP_ERROR_CHECK(bridge_init());
    usb_start();
    wifi_start();
    time_apply();
    ssh_start();
    telnet_start();
    tls_selfsigned(false);              // first boot: HTTPS with a self-signed certificate
    web_start();
    ota_mark_valid_later();
    xTaskCreate(io_task, "io", 2048, NULL, 2, NULL);
    xTaskCreate(late_task, "late", 4096, NULL, 3, NULL);
    audit("system: %s %s started (%s)", s_dev_id, sys_version(), users_claimed() ? "initialised" : "waiting for setup in the web UI");
}
