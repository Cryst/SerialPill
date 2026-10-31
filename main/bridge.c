// UART driver and session hub: every console session (SSH, telnet, web, USB) gets the UART
// output through its own stream buffer; input from all sessions is merged into the UART.
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "freertos/stream_buffer.h"
#include "driver/uart.h"
#include "driver/gpio.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "app.h"

static const char *TAG = "bridge";

#define UART_PORT       UART_NUM_1
#define PIN_IO1         4           // micro-USB pin 2 (D-)
#define PIN_IO2         3           // micro-USB pin 3 (D+)
#define SESSION_BUF     4096
#define HISTORY_SIZE    8192

struct sp_session {
    bool used;
    char kind[8];
    char who[48];
    int64_t since;
    StreamBufferHandle_t rx;        // UART -> session
    bool overflow;
    uint32_t in_bytes;              // session -> UART
};

static sp_session_t s_sessions[SP_MAX_SESSIONS];
static SemaphoreHandle_t s_lock, s_tx_lock;
static uint8_t s_hist[HISTORY_SIZE];
static uint32_t s_hist_end;         // total bytes ever received (stream offset of the newest byte + 1)
static uint32_t s_tx_total;

esp_err_t bridge_apply_serial(void)
{
    uart_word_length_t bits = UART_DATA_8_BITS;
    switch (g_cfg.format[0]) {
        case '5': bits = UART_DATA_5_BITS; break;
        case '6': bits = UART_DATA_6_BITS; break;
        case '7': bits = UART_DATA_7_BITS; break;
    }
    uart_parity_t par = g_cfg.format[1] == 'E' ? UART_PARITY_EVEN : g_cfg.format[1] == 'O' ? UART_PARITY_ODD : UART_PARITY_DISABLE;
    uart_stop_bits_t stop = g_cfg.format[2] == '2' ? UART_STOP_BITS_2 : UART_STOP_BITS_1;
    uart_config_t uc = {
        .baud_rate = g_cfg.baud, .data_bits = bits, .parity = par, .stop_bits = stop,
        .flow_ctrl = UART_HW_FLOWCTRL_DISABLE, .source_clk = UART_SCLK_DEFAULT,
    };
    esp_err_t e = uart_param_config(UART_PORT, &uc);
    if (e != ESP_OK) return e;
    // default (Aruba AP-635 with a straight micro-USB cable): TX on pin 2 (GPIO4), RX on pin 3 (GPIO3)
    int tx = g_cfg.swap ? PIN_IO2 : PIN_IO1, rx = g_cfg.swap ? PIN_IO1 : PIN_IO2;
    e = uart_set_pin(UART_PORT, tx, rx, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    gpio_pullup_en(rx);             // idle-high line when nothing is connected
    ESP_LOGI(TAG, "UART %lu %s TX=GPIO%d RX=GPIO%d", (unsigned long)g_cfg.baud, g_cfg.format, tx, rx);
    return e;
}

static void rx_task(void *arg)
{
    static uint8_t conv[512];
    static bool s_prev_cr;
    uint8_t buf[256];
    for (;;) {
        int n = uart_read_bytes(UART_PORT, buf, sizeof buf, pdMS_TO_TICKS(20));
        if (n <= 0) continue;
        // interactive sessions may get bare LF expanded to CRLF; history/API keep the raw stream
        const uint8_t *out = buf;
        size_t on = n;
        if (g_cfg.out_crlf) {
            on = 0;
            for (int i = 0; i < n; i++) {
                if (buf[i] == '\n' && !s_prev_cr) conv[on++] = '\r';
                conv[on++] = buf[i];
                s_prev_cr = buf[i] == '\r';
            }
            out = conv;
        } else if (n) {
            s_prev_cr = buf[n - 1] == '\r';
        }
        xSemaphoreTake(s_lock, portMAX_DELAY);
        for (int i = 0; i < n; i++) s_hist[(s_hist_end + i) % HISTORY_SIZE] = buf[i];
        s_hist_end += n;
        for (int i = 0; i < SP_MAX_SESSIONS; i++) {
            sp_session_t *s = &s_sessions[i];
            if (!s->used) continue;
            if (xStreamBufferSend(s->rx, out, on, 0) != on) s->overflow = true;   // slow consumer: drop
        }
        xSemaphoreGive(s_lock);
    }
}

esp_err_t bridge_init(void)
{
    s_lock = xSemaphoreCreateMutex();
    s_tx_lock = xSemaphoreCreateMutex();
    esp_err_t e = uart_driver_install(UART_PORT, 4096, 2048, 0, NULL, 0);
    if (e != ESP_OK) return e;
    bridge_apply_serial();
    xTaskCreate(rx_task, "uart_rx", 3072, NULL, 12, NULL);
    return ESP_OK;
}

sp_session_t *bridge_open(const char *kind, const char *who)
{
    sp_session_t *r = NULL;
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < SP_MAX_SESSIONS; i++) {
        if (s_sessions[i].used) continue;
        StreamBufferHandle_t sb = xStreamBufferCreate(SESSION_BUF, 1);
        if (!sb) break;
        r = &s_sessions[i];
        memset(r, 0, sizeof *r);
        r->used = true;
        r->rx = sb;
        r->since = esp_timer_get_time();
        snprintf(r->kind, sizeof r->kind, "%s", kind);
        snprintf(r->who, sizeof r->who, "%s", who);
        break;
    }
    xSemaphoreGive(s_lock);
    if (r) audit("console: %s session opened by %s", kind, who);
    else audit("console: %s session for %s refused (limit %d)", kind, who, SP_MAX_SESSIONS);
    return r;
}

void bridge_close(sp_session_t *s)
{
    if (!s) return;
    audit("console: %s session of %s closed", s->kind, s->who);
    xSemaphoreTake(s_lock, portMAX_DELAY);
    vStreamBufferDelete(s->rx);
    s->rx = NULL;
    s->used = false;
    xSemaphoreGive(s_lock);
}

size_t bridge_read(sp_session_t *s, uint8_t *buf, size_t len, uint32_t timeout_ms)
{
    return xStreamBufferReceive(s->rx, buf, len, pdMS_TO_TICKS(timeout_ms));
}

bool bridge_session_overflowed(sp_session_t *s)
{
    bool o = s->overflow;
    s->overflow = false;
    return o;
}

void bridge_write(sp_session_t *s, const uint8_t *d, size_t n)
{
    if (!n) return;
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    uart_write_bytes(UART_PORT, d, n);      // blocks while the 2 KB TX ring is full
    s_tx_total += n;
    if (s) s->in_bytes += n;
    xSemaphoreGive(s_tx_lock);
}

void bridge_send_break(void)
{
    // 300 ms of space condition (TX held low by inverting the idle line): treated as BREAK by
    // boot loaders/ROM monitors at any baud rate
    xSemaphoreTake(s_tx_lock, portMAX_DELAY);
    uart_wait_tx_done(UART_PORT, pdMS_TO_TICKS(1000));
    uart_set_line_inverse(UART_PORT, UART_SIGNAL_TXD_INV);
    vTaskDelay(pdMS_TO_TICKS(300));
    uart_set_line_inverse(UART_PORT, UART_SIGNAL_INV_DISABLE);
    vTaskDelay(pdMS_TO_TICKS(20));
    xSemaphoreGive(s_tx_lock);
    audit("console: BREAK sent");
}

size_t bridge_history(uint32_t since, uint8_t *buf, size_t len, uint32_t *next, uint32_t *end)
{
    xSemaphoreTake(s_lock, portMAX_DELAY);
    uint32_t start = s_hist_end > HISTORY_SIZE ? s_hist_end - HISTORY_SIZE : 0;
    if (since < start || since > s_hist_end) since = start;
    size_t n = s_hist_end - since;
    if (n > len) n = len;
    for (size_t i = 0; i < n; i++) buf[i] = s_hist[(since + i) % HISTORY_SIZE];
    *next = since + n;
    *end = s_hist_end;
    xSemaphoreGive(s_lock);
    return n;
}

uint32_t bridge_rx_total(void) { return s_hist_end; }
uint32_t bridge_tx_total(void) { return s_tx_total; }

cJSON *bridge_sessions_json(void)
{
    cJSON *a = cJSON_CreateArray();
    int64_t now = esp_timer_get_time();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < SP_MAX_SESSIONS; i++) {
        sp_session_t *s = &s_sessions[i];
        if (!s->used) continue;
        cJSON *o = cJSON_CreateObject();
        cJSON_AddStringToObject(o, "kind", s->kind);
        cJSON_AddStringToObject(o, "who", s->who);
        cJSON_AddNumberToObject(o, "seconds", (double)((now - s->since) / 1000000));
        cJSON_AddNumberToObject(o, "sent", s->in_bytes);
        cJSON_AddItemToArray(a, o);
    }
    xSemaphoreGive(s_lock);
    return a;
}

size_t console_echo(sp_console_t *c, const uint8_t *in, size_t n, uint8_t *out)
{
    size_t o = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        bool was_cr = c->echo_cr;
        c->echo_cr = ch == '\r';
        if (ch == '\r' || (ch == '\n' && !was_cr)) { out[o++] = '\r'; out[o++] = '\n'; }
        else if ((ch == '\n' || ch == 0) && was_cr) continue;   // second half of CRLF / CR NUL
        else if (ch == 0x7f || ch == 8) { out[o++] = 8; out[o++] = ' '; out[o++] = 8; }
        else if (ch != 0x1d) out[o++] = ch;
    }
    return o;
}

void console_banner(char *out, size_t sz)
{
    size_t o = 0;
    out[0] = 0;
    if (!g_cfg.banner[0] || sz < 8) return;
    out[o++] = '\r';
    out[o++] = '\n';
    for (const char *p = g_cfg.banner; *p && o + 6 < sz; p++) {
        if (*p == '\n') out[o++] = '\r';
        out[o++] = *p;
    }
    memcpy(out + o, "\r\n\r\n", 5);
}

// Ctrl+] opens a one-key menu: b = BREAK, q = disconnect, s = status, ? = help.
int console_filter(sp_console_t *c, const uint8_t *in, size_t n, uint8_t *out, char *reply, size_t rl)
{
    size_t o = 0;
    reply[0] = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t ch = in[i];
        if (c->menu) {
            c->menu = false;
            switch (ch) {
                case 'b': case 'B':
                    bridge_send_break();
                    snprintf(reply, rl, "\r\n[serialpill] BREAK sent\r\n");
                    break;
                case 'q': case 'Q': case '.':
                    snprintf(reply, rl, "\r\n[serialpill] disconnected\r\n");
                    return -1;
                case 's': case 'S':
                    snprintf(reply, rl, "\r\n[serialpill] %s, %lu %s%s, rx %lu B, tx %lu B\r\n", sys_device_id(),
                             (unsigned long)g_cfg.baud, g_cfg.format, g_cfg.swap ? " (RX/TX swapped)" : "",
                             (unsigned long)bridge_rx_total(), (unsigned long)bridge_tx_total());
                    break;
                case 0x1d:                  // Ctrl+] twice sends a literal Ctrl+]
                    out[o++] = ch;
                    break;
                default:
                    snprintf(reply, rl, "\r\n[serialpill] Ctrl+] then: b=BREAK  s=status  q=disconnect  Ctrl+]=send ^]\r\n");
            }
            continue;
        }
        if (ch == 0x1d) { c->menu = true; continue; }
        if (strcmp(g_cfg.enter, "raw") == 0) {
            out[o++] = ch;
            continue;
        }
        // one Enter from any client (CR, CRLF, CR NUL or bare LF) -> exactly one configured EOL
        bool was_cr = c->last_cr;
        c->last_cr = false;
        if (ch == '\r' || (ch == '\n' && !was_cr)) {
            if (g_cfg.enter[0] == 'c') out[o++] = '\r';
            if (strcmp(g_cfg.enter, "cr")) out[o++] = '\n';
            c->last_cr = ch == '\r';
            continue;
        }
        if ((ch == '\n' || ch == 0) && was_cr) continue;     // second half of CRLF / CR NUL
        out[o++] = ch;
    }
    return (int)o;
}
