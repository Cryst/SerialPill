// SerialPill - wireless UART console server for The Pill by Shelly (ESP32-C3)
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define SP_MAX_USERS        8
#define SP_MAX_KEYS         8       // authorized keys per user
#define SP_USER_LEN         32
#define SP_MAX_SESSIONS     6       // concurrent console sessions (ssh + telnet + web + usb)

// ---------------------------------------------------------------- config.c
typedef struct {
    // network
    bool wifi_sta;                  // false: own access point (factory default), true: client of wifi_ssid
    char ap_ssid[33];               // empty: "SerialPill-XXXXXX"
    char ap_pass[65];               // WPA2-PSK, 8..63 characters
    char wifi_ssid[33];
    char wifi_pass[65];
    char hostname[33];
    bool static_ip;
    char ip[16], mask[16], gw[16], dns[16];
    // serial
    uint32_t baud;
    char format[4];                 // "8N1"
    bool swap;                      // false: TX=GPIO4 (pin 2), RX=GPIO3 (pin 3) - Aruba AP-635 straight cable
    bool usb_bridge;                // USB-C is a transparent COM port (else: log console)
    char enter[5];                  // Enter from a client: "raw" (unchanged), "cr", "lf", "crlf"
    bool out_crlf;                  // device output: bare LF -> CRLF for interactive sessions
    // access
    bool ssh_en;
    uint16_t ssh_port;
    bool ssh_password;              // allow password auth (public keys always allowed)
    bool telnet_en;
    uint16_t telnet_port;
    bool https_redirect;            // redirect HTTP to HTTPS when a certificate is installed
    uint16_t idle_timeout;          // console session idle timeout, minutes (0 = never)
    uint16_t web_timeout;           // web login expires after this many idle minutes (0 = never)
    bool echo;                      // echo typed characters back to SSH/telnet console sessions
    char banner[512];               // login banner for SSH, telnet and the web login (\n line breaks)
    // TACACS+
    bool tac_en;
    char tac_host[64];
    uint16_t tac_port;
    char tac_key[65];
    uint8_t tac_timeout;            // seconds
    bool tac_pap;                   // PAP instead of ASCII login
    bool tac_fallback;              // local users when the server is unreachable
    bool tac_admin;                 // TACACS users may administer the device (web)
    // logging
    char syslog_host[64];
    // device
    char name[65];                  // friendly device name (empty = hostname)
    char ntp_server[64];
    char tz[64];                    // POSIX TZ string, e.g. CET-1CEST,M3.5.0,M10.5.0/3
    bool auth_skip;                 // first setup skipped: web UI open without a password (no users yet)
} sp_config_t;

extern sp_config_t g_cfg;

esp_err_t config_init(void);
esp_err_t config_save(void);
void config_defaults(sp_config_t *c);
cJSON *config_to_json(bool include_secrets);
esp_err_t config_from_json(const cJSON *j, char *err, size_t errlen);
esp_err_t config_blob_get(const char *key, void **data, size_t *len);   // caller frees
esp_err_t config_blob_set(const char *key, const void *data, size_t len);
esp_err_t config_blob_erase(const char *key);
void time_apply(void);                  // NTP server and time zone from g_cfg

// HTTPS certificate: self-signed one created on first boot (or on request)
esp_err_t tls_selfsigned(bool force);
bool tls_is_selfsigned(void);
void config_factory_reset(void);

// ---------------------------------------------------------------- users.c
typedef enum { ROLE_OPERATOR = 0, ROLE_ADMIN = 1 } sp_role_t;
typedef enum { AUTH_FAIL = 0, AUTH_OK = 1, AUTH_LOCKED = 2 } sp_auth_result_t;

typedef struct {
    char name[SP_USER_LEN + 1];
    sp_role_t role;
    bool tacacs;                    // authenticated through TACACS+
} sp_identity_t;

esp_err_t users_init(void);
bool users_claimed(void);           // an admin password has been set
esp_err_t users_set_password(const char *user, const char *pass, sp_role_t role, bool create);
esp_err_t users_delete(const char *user);
cJSON *users_to_json(void);
sp_auth_result_t auth_password(const char *user, const char *pass, const char *peer, const char *service, sp_identity_t *id);
bool auth_pubkey_allowed(const char *user, const char *algo, const uint8_t *blob, size_t len, sp_identity_t *id);
esp_err_t users_add_key(const char *user, const char *line, char *err, size_t errlen);
esp_err_t users_del_key(const char *user, int index);
int users_add_keys_text(const char *user, const char *text);   // ssh-copy-id: returns keys added
esp_err_t users_import_shelly_ha1(const char *realm, const char *ha1_hex);

// ---------------------------------------------------------------- tacacs.c
typedef enum { TAC_PASS, TAC_FAIL, TAC_ERROR } tac_result_t;
tac_result_t tacacs_authenticate(const char *user, const char *pass, const char *port, const char *rem_addr, char *msg, size_t msglen);

// ---------------------------------------------------------------- audit.c
void audit_init(void);
void audit(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
cJSON *audit_to_json(void);

// ---------------------------------------------------------------- bridge.c (UART + session hub)
typedef struct sp_session sp_session_t;
esp_err_t bridge_init(void);
esp_err_t bridge_apply_serial(void);
sp_session_t *bridge_open(const char *kind, const char *who);
void bridge_close(sp_session_t *s);
size_t bridge_read(sp_session_t *s, uint8_t *buf, size_t len, uint32_t timeout_ms);
void bridge_write(sp_session_t *s, const uint8_t *data, size_t len);
void bridge_send_break(void);
bool bridge_session_overflowed(sp_session_t *s);
size_t bridge_history(uint32_t since, uint8_t *buf, size_t len, uint32_t *next, uint32_t *end);
cJSON *bridge_sessions_json(void);
uint32_t bridge_rx_total(void);
uint32_t bridge_tx_total(void);

// console session helper shared by ssh/telnet/usb: handles the Ctrl+] escape menu
typedef struct {
    sp_session_t *s;
    bool menu;
    bool last_cr;                   // previous input byte was CR (CRLF / CR NUL = one Enter)
    bool echo_cr;                   // local echo: previous echoed byte was CR
} sp_console_t;
// filters input from the user; returns bytes to forward to the UART in out (out must hold 2*n
// bytes: Enter may become CRLF), or -1 to disconnect
int console_filter(sp_console_t *c, const uint8_t *in, size_t n, uint8_t *out, char *reply, size_t replylen);
// local echo of the bytes forwarded to the UART (console_filter output): Enter shows as CRLF,
// backspace erases; out must hold 3*n bytes; returns the number of bytes to send to the client
size_t console_echo(sp_console_t *c, const uint8_t *in, size_t n, uint8_t *out);
// login banner with CRLF line breaks and a blank line after it ("" when no banner is set)
void console_banner(char *out, size_t sz);

// ---------------------------------------------------------------- network services
esp_err_t wifi_start(void);
bool wifi_connected(void);
const char *wifi_ip(void);
bool wifi_ap_mode(void);
cJSON *wifi_status_json(void);
cJSON *wifi_scan_json(void);

bool web_https_running(void);
esp_err_t ssh_start(void);
void ssh_update_banner(void);           // after the banner setting changed
const char *ssh_host_fingerprint(void);
esp_err_t telnet_start(void);
void telnet_stop(void);
esp_err_t web_start(void);
esp_err_t usb_start(void);

// ---------------------------------------------------------------- system
esp_err_t migrate_from_shelly(void);           // first boot after Shelly OTA
void migrate_import_shelly_config(void);
void migrate_guard_other_slot(void);              // every boot: no foreign image in the other slot
esp_err_t ota_begin_upload(size_t size, void **handle, char *err, size_t errlen);
esp_err_t ota_write_chunk(void *handle, const uint8_t *d, size_t n, char *err, size_t errlen);
esp_err_t ota_finish(void *handle, char *err, size_t errlen);
void ota_abort(void *handle);
void ota_mark_valid_later(void);

// Shelly restore: streamed official package
typedef struct shelly_restore shelly_restore_t;
esp_err_t shelly_restore_prepare(char *err, size_t errlen);   // ensure SerialPill runs from app_1
shelly_restore_t *shelly_restore_begin(char *err, size_t errlen);
esp_err_t shelly_restore_feed(shelly_restore_t *r, const uint8_t *d, size_t n, char *err, size_t errlen);
esp_err_t shelly_restore_finish(shelly_restore_t *r, char *err, size_t errlen);
void shelly_restore_abort(shelly_restore_t *r);
esp_err_t shelly_restore_from_server(const char *channel, char *err, size_t errlen);
esp_err_t shelly_check_server(cJSON **out, char *err, size_t errlen);
esp_err_t firmware_from_url(const char *url, char *err, size_t errlen);   // SerialPill .bin or Shelly .zip
int shelly_restore_progress(void);
const char *shelly_restore_state(void);

void sys_reboot_later(uint32_t ms);
const char *sys_version(void);
const char *sys_device_id(void);       // serialpill-<mac>
