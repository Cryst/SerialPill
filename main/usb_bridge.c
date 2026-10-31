// USB-C (USB Serial/JTAG) as a transparent COM port to the UART. The host-side baud rate is
// irrelevant: the UART speed is set in the configuration.
//
// The USB Serial/JTAG FIFOs are polled through the HAL instead of using the interrupt-driven
// driver: with the driver installed and no host reading the port, its interrupt kept firing and
// starved the system. Polling every few milliseconds is plenty for a console and cannot stall:
// output is written only while the host drains the 64-byte FIFO, otherwise it is dropped.
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "hal/usb_serial_jtag_ll.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "app.h"

#define POLL_MS        5
#define HOST_GONE_US   100000      // FIFO not drained for 100 ms: no terminal on the host side

static int quiet_vprintf(const char *fmt, va_list ap) { (void)fmt; (void)ap; return 0; }

static int64_t s_last_drain;

// writes as much as the host takes; returns false when the host is not reading
static bool usb_write(const uint8_t *d, size_t n)
{
    while (n) {
        if (!usb_serial_jtag_ll_txfifo_writable()) {
            if (esp_timer_get_time() - s_last_drain > HOST_GONE_US) return false;
            vTaskDelay(1);
            continue;
        }
        int w = usb_serial_jtag_ll_write_txfifo(d, n);
        usb_serial_jtag_ll_txfifo_flush();
        s_last_drain = esp_timer_get_time();
        d += w;
        n -= w;
    }
    return true;
}

static void usb_task(void *arg)
{
    sp_session_t *s = bridge_open("usb", "USB-C");
    if (!s) vTaskDelete(NULL);
    sp_console_t con = { .s = s };
    uint8_t in[64], out[128], rx[256];
    char reply[160];
    bool host = false;
    for (;;) {
        // host -> UART
        if (usb_serial_jtag_ll_rxfifo_data_available()) {
            int n = usb_serial_jtag_ll_read_rxfifo(in, sizeof in);
            if (n > 0) {
                host = true;
                s_last_drain = esp_timer_get_time();
                int m = console_filter(&con, in, n, out, reply, sizeof reply);
                if (reply[0]) usb_write((const uint8_t *)reply, strlen(reply));
                if (m > 0) bridge_write(s, out, m);
            }
        }
        // UART -> host (dropped while no terminal is reading)
        size_t r = bridge_read(s, rx, sizeof rx, POLL_MS);
        if (usb_serial_jtag_ll_txfifo_writable()) host = true;
        if (r && host && !usb_write(rx, r)) host = false;
        bridge_session_overflowed(s);
    }
}

esp_err_t usb_start(void)
{
    if (!g_cfg.usb_bridge) return ESP_OK;
    ESP_LOGI("usb", "USB-C becomes a console COM port; log output disabled");
    esp_log_set_vprintf(quiet_vprintf);     // the console must not write to the same FIFO
    return xTaskCreate(usb_task, "usb_bridge", 3072, NULL, 6, NULL) == pdPASS ? ESP_OK : ESP_FAIL;
}
