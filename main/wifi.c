// WiFi: factory default is a WPA2 access point "SerialPill-XXXXXX" (password in the config,
// default "serialpill"). In client mode it joins the configured network; the AP is not
// started on WiFi outages (button held 10 s = factory reset brings the AP back).
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "lwip/ip4_addr.h"
#include "mdns.h"
#include "app.h"

static const char *TAG = "wifi";
static esp_netif_t *s_sta, *s_ap;
static bool s_connected, s_ap_mode;
static char s_ip[16] = "";
static int s_retries;

static void on_event(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    if (base == WIFI_EVENT && id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (base == WIFI_EVENT && id == WIFI_EVENT_STA_DISCONNECTED) {
        wifi_event_sta_disconnected_t *d = data;
        if (s_connected) audit("wifi: disconnected (reason %d)", d->reason);
        s_connected = false;
        s_ip[0] = 0;
        // back off up to 30 s between attempts
        int delay = s_retries < 5 ? 1000 : s_retries < 20 ? 5000 : 30000;
        s_retries++;
        vTaskDelay(pdMS_TO_TICKS(delay));
        esp_wifi_connect();
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *e = data;
        snprintf(s_ip, sizeof s_ip, IPSTR, IP2STR(&e->ip_info.ip));
        s_connected = true;
        s_retries = 0;
        audit("wifi: connected to '%s', IP %s", g_cfg.wifi_ssid, s_ip);
    }
}

static void apply_static_ip(void)
{
    if (!g_cfg.static_ip) return;
    esp_netif_dhcpc_stop(s_sta);
    esp_netif_ip_info_t ip = { 0 };
    ip.ip.addr = ipaddr_addr(g_cfg.ip);
    ip.netmask.addr = ipaddr_addr(g_cfg.mask);
    ip.gw.addr = g_cfg.gw[0] ? ipaddr_addr(g_cfg.gw) : 0;
    esp_netif_set_ip_info(s_sta, &ip);
    if (g_cfg.dns[0]) {
        esp_netif_dns_info_t dns = { .ip.u_addr.ip4.addr = ipaddr_addr(g_cfg.dns), .ip.type = ESP_IPADDR_TYPE_V4 };
        esp_netif_set_dns_info(s_sta, ESP_NETIF_DNS_MAIN, &dns);
    }
}

esp_err_t wifi_start(void)
{
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    s_sta = esp_netif_create_default_wifi_sta();
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    esp_wifi_set_storage(WIFI_STORAGE_RAM);       // credentials live in our config, not in the WiFi NVS
    esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, on_event, NULL);
    esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, on_event, NULL);
    esp_netif_set_hostname(s_sta, g_cfg.hostname);

    if (g_cfg.wifi_sta && g_cfg.wifi_ssid[0]) {
        wifi_config_t wc = { 0 };
        snprintf((char *)wc.sta.ssid, sizeof wc.sta.ssid, "%s", g_cfg.wifi_ssid);
        snprintf((char *)wc.sta.password, sizeof wc.sta.password, "%s", g_cfg.wifi_pass);
        wc.sta.threshold.authmode = g_cfg.wifi_pass[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
        wc.sta.pmf_cfg.capable = true;
        wc.sta.scan_method = WIFI_ALL_CHANNEL_SCAN;
        wc.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
        esp_wifi_set_mode(WIFI_MODE_STA);
        esp_wifi_set_config(WIFI_IF_STA, &wc);
        apply_static_ip();
    } else {
        s_ap = esp_netif_create_default_wifi_ap();
        // AP address 192.168.33.1/24 (DHCP hands out 192.168.33.2+)
        esp_netif_dhcps_stop(s_ap);
        esp_netif_ip_info_t aip = { 0 };
        esp_netif_set_ip4_addr(&aip.ip, 192, 168, 33, 1);
        esp_netif_set_ip4_addr(&aip.gw, 192, 168, 33, 1);
        esp_netif_set_ip4_addr(&aip.netmask, 255, 255, 255, 0);
        esp_netif_set_ip_info(s_ap, &aip);
        esp_netif_dhcps_start(s_ap);
        uint8_t mac[6];
        esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
        wifi_config_t ac = { .ap = { .channel = 6, .max_connection = 4, .authmode = WIFI_AUTH_WPA2_PSK,
                                     .pmf_cfg = { .capable = true } } };
        int n = g_cfg.ap_ssid[0]
              ? snprintf((char *)ac.ap.ssid, sizeof ac.ap.ssid, "%s", g_cfg.ap_ssid)
              : snprintf((char *)ac.ap.ssid, sizeof ac.ap.ssid, "SerialPill-%02X%02X%02X", mac[3], mac[4], mac[5]);
        ac.ap.ssid_len = n;
        snprintf((char *)ac.ap.password, sizeof ac.ap.password, "%s", g_cfg.ap_pass);
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_set_config(WIFI_IF_AP, &ac);
        s_ap_mode = true;
        audit("wifi: WPA2 access point '%s' at http://192.168.33.1/", ac.ap.ssid);
    }
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    ESP_ERROR_CHECK(esp_wifi_start());

    if (mdns_init() == ESP_OK) {
        mdns_hostname_set(g_cfg.hostname);
        mdns_instance_name_set("SerialPill console server");
        mdns_service_add(NULL, "_http", "_tcp", 80, NULL, 0);
        if (g_cfg.ssh_en) mdns_service_add(NULL, "_ssh", "_tcp", g_cfg.ssh_port, NULL, 0);
    }
    return ESP_OK;
}

bool wifi_connected(void) { return s_connected; }
const char *wifi_ip(void) { return s_ip; }
bool wifi_ap_mode(void) { return s_ap_mode; }

cJSON *wifi_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    cJSON_AddBoolToObject(o, "connected", s_connected);
    cJSON_AddStringToObject(o, "ssid", g_cfg.wifi_ssid);
    cJSON_AddStringToObject(o, "ip", s_ip);
    cJSON_AddBoolToObject(o, "setup_ap", s_ap_mode);
    cJSON_AddStringToObject(o, "mode", s_ap_mode ? "ap" : "sta");
    wifi_ap_record_t ap;
    if (s_connected && esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
        cJSON_AddNumberToObject(o, "rssi", ap.rssi);
        cJSON_AddNumberToObject(o, "channel", ap.primary);
    }
    uint8_t mac[6];
    char m[18];
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    snprintf(m, sizeof m, MACSTR, MAC2STR(mac));
    cJSON_AddStringToObject(o, "mac", m);
    return o;
}

cJSON *wifi_scan_json(void)
{
    cJSON *a = cJSON_CreateArray();
    wifi_scan_config_t sc = { .show_hidden = false };
    if (esp_wifi_scan_start(&sc, true) != ESP_OK) return a;
    uint16_t n = 20;
    wifi_ap_record_t *recs = calloc(n, sizeof *recs);
    if (recs && esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) {
        for (int i = 0; i < n; i++) {
            cJSON *o = cJSON_CreateObject();
            cJSON_AddStringToObject(o, "ssid", (const char *)recs[i].ssid);
            cJSON_AddNumberToObject(o, "rssi", recs[i].rssi);
            cJSON_AddBoolToObject(o, "secure", recs[i].authmode != WIFI_AUTH_OPEN);
            cJSON_AddItemToArray(a, o);
        }
    }
    free(recs);
    return a;
}
