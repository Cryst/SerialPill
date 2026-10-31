// Persistent configuration: one JSON document in NVS plus binary blobs (keys, certificates).
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "nvs_flash.h"
#include "nvs.h"
#include "app.h"

static const char *TAG = "config";
static const char *NS = "serialpill";

#ifndef SP_USB_BRIDGE_DEFAULT
#define SP_USB_BRIDGE_DEFAULT 1     // USB-C is a console COM port unless a debug build says otherwise
#endif
#ifndef SP_AP_PASS_DEFAULT
#define SP_AP_PASS_DEFAULT "serialpill"   // factory WPA2 password of the access point
#endif
sp_config_t g_cfg;

void config_defaults(sp_config_t *c)
{
    memset(c, 0, sizeof(*c));
    snprintf(c->hostname, sizeof(c->hostname), "%s", sys_device_id());
    c->wifi_sta = false;            // factory: WPA2 access point
    strcpy(c->ap_pass, SP_AP_PASS_DEFAULT);
    c->baud = 9600;                 // Aruba AP console default
    strcpy(c->format, "8N1");
    c->swap = false;
    c->usb_bridge = SP_USB_BRIDGE_DEFAULT;
    strcpy(c->enter, "raw");         // transparent by default (binary transfers, XMODEM)
    c->out_crlf = false;
    c->ssh_en = true;
    c->ssh_port = 22;
    c->ssh_password = true;
    c->telnet_en = false;
    c->telnet_port = 23;
    c->https_redirect = false;      // the self-signed certificate would always warn; asked during setup
    c->idle_timeout = 0;
    c->web_timeout = 0;             // no automatic logout by default
    c->echo = true;
    strcpy(c->banner, "SerialPill console server - authorized access only.\nAll connections are logged.");
    c->tac_port = 49;
    c->tac_timeout = 5;
    c->tac_fallback = true;
    strcpy(c->ntp_server, "pool.ntp.org");
    strcpy(c->tz, "UTC0");
}

#define SECRET_MASK "********"

cJSON *config_to_json(bool secrets)
{
    const sp_config_t *c = &g_cfg;
    cJSON *j = cJSON_CreateObject();
    cJSON *n = cJSON_AddObjectToObject(j, "network");
    cJSON_AddStringToObject(n, "wifi_mode", c->wifi_sta ? "sta" : "ap");
    cJSON_AddStringToObject(n, "ap_ssid", c->ap_ssid);
    cJSON_AddStringToObject(n, "ap_pass", secrets ? c->ap_pass : SECRET_MASK);
    cJSON_AddStringToObject(n, "wifi_ssid", c->wifi_ssid);
    cJSON_AddStringToObject(n, "wifi_pass", secrets ? c->wifi_pass : (c->wifi_pass[0] ? SECRET_MASK : ""));
    cJSON_AddStringToObject(n, "hostname", c->hostname);
    cJSON_AddBoolToObject(n, "static_ip", c->static_ip);
    cJSON_AddStringToObject(n, "ip", c->ip);
    cJSON_AddStringToObject(n, "mask", c->mask);
    cJSON_AddStringToObject(n, "gw", c->gw);
    cJSON_AddStringToObject(n, "dns", c->dns);
    cJSON *s = cJSON_AddObjectToObject(j, "serial");
    cJSON_AddNumberToObject(s, "baud", c->baud);
    cJSON_AddStringToObject(s, "format", c->format);
    cJSON_AddBoolToObject(s, "swap", c->swap);
    cJSON_AddBoolToObject(s, "usb_bridge", c->usb_bridge);
    cJSON_AddStringToObject(s, "enter", c->enter);
    cJSON_AddBoolToObject(s, "out_crlf", c->out_crlf);
    cJSON *a = cJSON_AddObjectToObject(j, "access");
    cJSON_AddBoolToObject(a, "ssh_en", c->ssh_en);
    cJSON_AddNumberToObject(a, "ssh_port", c->ssh_port);
    cJSON_AddBoolToObject(a, "ssh_password", c->ssh_password);
    cJSON_AddBoolToObject(a, "telnet_en", c->telnet_en);
    cJSON_AddNumberToObject(a, "telnet_port", c->telnet_port);
    cJSON_AddBoolToObject(a, "https_redirect", c->https_redirect);
    cJSON_AddNumberToObject(a, "idle_timeout", c->idle_timeout);
    cJSON_AddNumberToObject(a, "web_timeout", c->web_timeout);
    cJSON_AddBoolToObject(a, "echo", c->echo);
    cJSON_AddStringToObject(a, "banner", c->banner);
    cJSON *t = cJSON_AddObjectToObject(j, "tacacs");
    cJSON_AddBoolToObject(t, "enable", c->tac_en);
    cJSON_AddStringToObject(t, "host", c->tac_host);
    cJSON_AddNumberToObject(t, "port", c->tac_port);
    cJSON_AddStringToObject(t, "key", secrets ? c->tac_key : (c->tac_key[0] ? SECRET_MASK : ""));
    cJSON_AddNumberToObject(t, "timeout", c->tac_timeout);
    cJSON_AddBoolToObject(t, "pap", c->tac_pap);
    cJSON_AddBoolToObject(t, "fallback", c->tac_fallback);
    cJSON_AddBoolToObject(t, "admin", c->tac_admin);
    cJSON *l = cJSON_AddObjectToObject(j, "log");
    cJSON_AddStringToObject(l, "syslog_host", c->syslog_host);
    cJSON *y = cJSON_AddObjectToObject(j, "system");
    cJSON_AddStringToObject(y, "name", c->name);
    cJSON_AddStringToObject(y, "ntp_server", c->ntp_server);
    cJSON_AddStringToObject(y, "timezone", c->tz);
    cJSON_AddBoolToObject(y, "auth_skip", c->auth_skip);
    return j;
}

// ---- typed field helpers with validation
static bool get_str(const cJSON *o, const char *k, char *dst, size_t sz, bool secret, char *err, size_t el)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsString(v)) { snprintf(err, el, "%s: string expected", k); return false; }
    if (secret && strcmp(v->valuestring, SECRET_MASK) == 0) return true;   // unchanged
    if (strlen(v->valuestring) >= sz) { snprintf(err, el, "%s: too long (max %u)", k, (unsigned)sz - 1); return false; }
    strcpy(dst, v->valuestring);
    return true;
}

static bool get_bool(const cJSON *o, const char *k, bool *dst, char *err, size_t el)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsBool(v)) { snprintf(err, el, "%s: boolean expected", k); return false; }
    *dst = cJSON_IsTrue(v);
    return true;
}

static bool get_num(const cJSON *o, const char *k, double min, double max, double *dst, char *err, size_t el)
{
    const cJSON *v = cJSON_GetObjectItemCaseSensitive(o, k);
    if (!v) return true;
    if (!cJSON_IsNumber(v) || v->valuedouble < min || v->valuedouble > max || v->valuedouble != (double)(long long)v->valuedouble) {
        snprintf(err, el, "%s: integer %.0f..%.0f expected", k, min, max);
        return false;
    }
    *dst = v->valuedouble;
    return true;
}

static bool valid_ip(const char *s)
{
    if (!*s) return true;
    unsigned a, b, c, d; char x;
    return sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &x) == 4 && a < 256 && b < 256 && c < 256 && d < 256;
}

// banner: printable text, tabs and line breaks (CR removed); no control or escape sequences
static bool valid_banner(char *s)
{
    char *w = s;
    for (char *r = s; *r; r++) {
        unsigned char ch = (unsigned char)*r;
        if (ch == '\r') continue;
        if ((ch < 32 && ch != '\n' && ch != '\t') || ch == 0x7f) return false;
        *w++ = (char)ch;
    }
    *w = 0;
    return true;
}

static bool valid_hostname(const char *s)
{
    if (!*s) return false;
    for (; *s; s++)
        if (!((*s >= 'a' && *s <= 'z') || (*s >= 'A' && *s <= 'Z') || (*s >= '0' && *s <= '9') || *s == '-')) return false;
    return true;
}

esp_err_t config_from_json(const cJSON *j, char *err, size_t el)
{
    sp_config_t c = g_cfg;
    double d;
    const cJSON *o;
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "network"))) {
        if (!get_str(o, "wifi_ssid", c.wifi_ssid, sizeof c.wifi_ssid, false, err, el) ||
            !get_str(o, "wifi_pass", c.wifi_pass, sizeof c.wifi_pass, true, err, el) ||
            !get_str(o, "hostname", c.hostname, sizeof c.hostname, false, err, el) ||
            !get_bool(o, "static_ip", &c.static_ip, err, el) ||
            !get_str(o, "ip", c.ip, sizeof c.ip, false, err, el) ||
            !get_str(o, "mask", c.mask, sizeof c.mask, false, err, el) ||
            !get_str(o, "gw", c.gw, sizeof c.gw, false, err, el) ||
            !get_str(o, "dns", c.dns, sizeof c.dns, false, err, el)) return ESP_ERR_INVALID_ARG;
        if (!get_str(o, "ap_ssid", c.ap_ssid, sizeof c.ap_ssid, false, err, el) ||
            !get_str(o, "ap_pass", c.ap_pass, sizeof c.ap_pass, true, err, el)) return ESP_ERR_INVALID_ARG;
        const cJSON *m = cJSON_GetObjectItemCaseSensitive(o, "wifi_mode");
        if (m) {
            if (!cJSON_IsString(m) || (strcmp(m->valuestring, "ap") && strcmp(m->valuestring, "sta"))) {
                snprintf(err, el, "wifi_mode: \"ap\" or \"sta\"");
                return ESP_ERR_INVALID_ARG;
            }
            c.wifi_sta = strcmp(m->valuestring, "sta") == 0;
        } else if (cJSON_GetObjectItemCaseSensitive(o, "wifi_ssid") && c.wifi_ssid[0]) {
            c.wifi_sta = true;      // configuration saved before wifi_mode existed
        }
        if (strlen(c.ap_pass) < 8 || strlen(c.ap_pass) > 63) { snprintf(err, el, "ap_pass: 8..63 characters"); return ESP_ERR_INVALID_ARG; }
        if (c.wifi_sta && !c.wifi_ssid[0]) { snprintf(err, el, "client mode needs wifi_ssid"); return ESP_ERR_INVALID_ARG; }
        if (c.wifi_pass[0] && (strlen(c.wifi_pass) < 8)) { snprintf(err, el, "wifi_pass: 8..64 characters"); return ESP_ERR_INVALID_ARG; }
        if (!valid_hostname(c.hostname)) { snprintf(err, el, "hostname: letters, digits and '-' only"); return ESP_ERR_INVALID_ARG; }
        if (!valid_ip(c.ip) || !valid_ip(c.mask) || !valid_ip(c.gw) || !valid_ip(c.dns)) { snprintf(err, el, "invalid IPv4 address"); return ESP_ERR_INVALID_ARG; }
        if (c.static_ip && (!c.ip[0] || !c.mask[0])) { snprintf(err, el, "static IP needs ip and mask"); return ESP_ERR_INVALID_ARG; }
    }
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "serial"))) {
        d = c.baud;
        if (!get_num(o, "baud", 300, 3000000, &d, err, el) ||
            !get_str(o, "format", c.format, sizeof c.format, false, err, el) ||
            !get_bool(o, "swap", &c.swap, err, el) ||
            !get_bool(o, "usb_bridge", &c.usb_bridge, err, el) ||
            !get_str(o, "enter", c.enter, sizeof c.enter, false, err, el) ||
            !get_bool(o, "out_crlf", &c.out_crlf, err, el)) return ESP_ERR_INVALID_ARG;
        if (strcmp(c.enter, "raw") && strcmp(c.enter, "cr") && strcmp(c.enter, "lf") && strcmp(c.enter, "crlf")) {
            snprintf(err, el, "enter: raw, cr, lf or crlf");
            return ESP_ERR_INVALID_ARG;
        }
        c.baud = (uint32_t)d;
        if (strlen(c.format) != 3 || !strchr("5678", c.format[0]) || !strchr("NEO", c.format[1]) || !strchr("12", c.format[2])) {
            snprintf(err, el, "format: e.g. 8N1 (data 5-8, parity N/E/O, stop 1/2)");
            return ESP_ERR_INVALID_ARG;
        }
    }
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "access"))) {
        if (!get_bool(o, "ssh_en", &c.ssh_en, err, el) || !get_bool(o, "ssh_password", &c.ssh_password, err, el) ||
            !get_bool(o, "telnet_en", &c.telnet_en, err, el) || !get_bool(o, "https_redirect", &c.https_redirect, err, el) ||
            !get_bool(o, "echo", &c.echo, err, el) || !get_str(o, "banner", c.banner, sizeof c.banner, false, err, el))
            return ESP_ERR_INVALID_ARG;
        if (!valid_banner(c.banner)) { snprintf(err, el, "banner: printable text and line breaks only"); return ESP_ERR_INVALID_ARG; }
        d = c.ssh_port; if (!get_num(o, "ssh_port", 1, 65535, &d, err, el)) return ESP_ERR_INVALID_ARG; c.ssh_port = d;
        d = c.telnet_port; if (!get_num(o, "telnet_port", 1, 65535, &d, err, el)) return ESP_ERR_INVALID_ARG; c.telnet_port = d;
        d = c.idle_timeout; if (!get_num(o, "idle_timeout", 0, 1440, &d, err, el)) return ESP_ERR_INVALID_ARG; c.idle_timeout = d;
        d = c.web_timeout; if (!get_num(o, "web_timeout", 0, 10080, &d, err, el)) return ESP_ERR_INVALID_ARG; c.web_timeout = d;
        if (c.ssh_port == 80 || c.ssh_port == 443 || c.telnet_port == 80 || c.telnet_port == 443 || (c.ssh_port == c.telnet_port)) {
            snprintf(err, el, "ports must differ and not use 80/443");
            return ESP_ERR_INVALID_ARG;
        }
    }
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "tacacs"))) {
        if (!get_bool(o, "enable", &c.tac_en, err, el) || !get_str(o, "host", c.tac_host, sizeof c.tac_host, false, err, el) ||
            !get_str(o, "key", c.tac_key, sizeof c.tac_key, true, err, el) || !get_bool(o, "pap", &c.tac_pap, err, el) ||
            !get_bool(o, "fallback", &c.tac_fallback, err, el) || !get_bool(o, "admin", &c.tac_admin, err, el))
            return ESP_ERR_INVALID_ARG;
        d = c.tac_port; if (!get_num(o, "port", 1, 65535, &d, err, el)) return ESP_ERR_INVALID_ARG; c.tac_port = d;
        d = c.tac_timeout; if (!get_num(o, "timeout", 1, 30, &d, err, el)) return ESP_ERR_INVALID_ARG; c.tac_timeout = d;
        if (c.tac_en && !c.tac_host[0]) { snprintf(err, el, "tacacs: host required"); return ESP_ERR_INVALID_ARG; }
    }
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "log"))) {
        if (!get_str(o, "syslog_host", c.syslog_host, sizeof c.syslog_host, false, err, el)) return ESP_ERR_INVALID_ARG;
    }
    if ((o = cJSON_GetObjectItemCaseSensitive(j, "system"))) {
        // auth_skip is set by the first setup only; here it can merely be cleared
        bool skip = c.auth_skip;
        if (!get_str(o, "name", c.name, sizeof c.name, false, err, el) ||
            !get_str(o, "ntp_server", c.ntp_server, sizeof c.ntp_server, false, err, el) ||
            !get_str(o, "timezone", c.tz, sizeof c.tz, false, err, el) || !get_bool(o, "auth_skip", &skip, err, el))
            return ESP_ERR_INVALID_ARG;
        if (!skip) c.auth_skip = false;
        if (!valid_banner(c.name) || strchr(c.name, '\n')) { snprintf(err, el, "name: one line of printable text"); return ESP_ERR_INVALID_ARG; }
        if (!c.ntp_server[0] || strspn(c.ntp_server, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-") != strlen(c.ntp_server)) {
            snprintf(err, el, "ntp_server: host name or IP address expected");
            return ESP_ERR_INVALID_ARG;
        }
        if (!c.tz[0] || strspn(c.tz, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+-,./:<>") != strlen(c.tz)) {
            snprintf(err, el, "timezone: POSIX TZ string expected, e.g. CET-1CEST,M3.5.0,M10.5.0/3");
            return ESP_ERR_INVALID_ARG;
        }
    }
    g_cfg = c;
    return ESP_OK;
}

esp_err_t config_save(void)
{
    cJSON *j = config_to_json(true);
    char *s = cJSON_PrintUnformatted(j);
    cJSON_Delete(j);
    if (!s) return ESP_ERR_NO_MEM;
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    if (e == ESP_OK) {
        e = nvs_set_str(h, "cfg", s);
        if (e == ESP_OK) e = nvs_commit(h);
        nvs_close(h);
    }
    free(s);
    if (e != ESP_OK) ESP_LOGE(TAG, "save failed: %s", esp_err_to_name(e));
    return e;
}

esp_err_t config_blob_get(const char *key, void **data, size_t *len)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READONLY, &h);
    if (e != ESP_OK) return e;
    size_t n = 0;
    e = nvs_get_blob(h, key, NULL, &n);
    if (e == ESP_OK) {
        *data = malloc(n + 1);          // +1: PEM users get a terminator
        if (!*data) e = ESP_ERR_NO_MEM;
        else if ((e = nvs_get_blob(h, key, *data, &n)) == ESP_OK) { ((char *)*data)[n] = 0; *len = n; }
        else free(*data);
    }
    nvs_close(h);
    return e;
}

esp_err_t config_blob_set(const char *key, const void *data, size_t len)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_blob(h, key, data, len);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

esp_err_t config_blob_erase(const char *key)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NS, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_erase_key(h, key);
    if (e == ESP_OK || e == ESP_ERR_NVS_NOT_FOUND) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

void config_factory_reset(void)
{
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READWRITE, &h) == ESP_OK) {
        nvs_erase_all(h);
        nvs_commit(h);
        nvs_close(h);
    }
}

esp_err_t config_init(void)
{
    esp_err_t e = nvs_flash_init();
    if (e == ESP_ERR_NVS_NO_FREE_PAGES || e == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        // first boot after Shelly: its NVS layout is not ours
        ESP_LOGW(TAG, "formatting NVS (%s)", esp_err_to_name(e));
        ESP_ERROR_CHECK(nvs_flash_erase());
        e = nvs_flash_init();
    }
    if (e != ESP_OK) return e;
    config_defaults(&g_cfg);
    nvs_handle_t h;
    if (nvs_open(NS, NVS_READONLY, &h) == ESP_OK) {
        size_t n = 0;
        if (nvs_get_str(h, "cfg", NULL, &n) == ESP_OK) {
            char *s = malloc(n);
            if (s && nvs_get_str(h, "cfg", s, &n) == ESP_OK) {
                cJSON *j = cJSON_Parse(s);
                char err[96] = "";
                if (!j || config_from_json(j, err, sizeof err) != ESP_OK) ESP_LOGE(TAG, "stored config invalid: %s", err);
                cJSON_Delete(j);
            }
            free(s);
        }
        nvs_close(h);
    }
    return ESP_OK;
}
