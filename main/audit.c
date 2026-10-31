// Security audit log: RAM ring buffer (web UI) + optional remote syslog (UDP/514, RFC 5424).
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "app.h"

#define AUDIT_ENTRIES 64
#define AUDIT_LEN     120

typedef struct { int64_t uptime; time_t wall; char msg[AUDIT_LEN]; } entry_t;

static entry_t s_ring[AUDIT_ENTRIES];
static int s_head, s_count;
static SemaphoreHandle_t s_lock;

void audit_init(void)
{
    s_lock = xSemaphoreCreateMutex();
}

static void syslog_send(const char *msg)
{
    if (!g_cfg.syslog_host[0] || !wifi_connected()) return;
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_DGRAM }, *res = NULL;
    if (getaddrinfo(g_cfg.syslog_host, "514", &hints, &res) != 0 || !res) return;
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        char buf[256];
        // facility auth(4), severity notice(5) -> PRI 37
        int n = snprintf(buf, sizeof buf, "<37>1 - %s serialpill - - - %s", g_cfg.hostname, msg);
        sendto(fd, buf, n, 0, res->ai_addr, res->ai_addrlen);
        close(fd);
    }
    freeaddrinfo(res);
}

void audit(const char *fmt, ...)
{
    char msg[AUDIT_LEN];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof msg, fmt, ap);
    va_end(ap);
    ESP_LOGI("audit", "%s", msg);
    if (s_lock) {
        xSemaphoreTake(s_lock, portMAX_DELAY);
        entry_t *e = &s_ring[s_head];
        e->uptime = esp_timer_get_time() / 1000000;
        e->wall = time(NULL);
        snprintf(e->msg, sizeof e->msg, "%s", msg);
        s_head = (s_head + 1) % AUDIT_ENTRIES;
        if (s_count < AUDIT_ENTRIES) s_count++;
        xSemaphoreGive(s_lock);
    }
    syslog_send(msg);
}

cJSON *audit_to_json(void)
{
    cJSON *a = cJSON_CreateArray();
    xSemaphoreTake(s_lock, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        entry_t *e = &s_ring[(s_head - s_count + i + AUDIT_ENTRIES) % AUDIT_ENTRIES];
        cJSON *o = cJSON_CreateObject();
        cJSON_AddNumberToObject(o, "uptime", (double)e->uptime);
        if (e->wall > 1700000000) cJSON_AddNumberToObject(o, "time", (double)e->wall);
        cJSON_AddStringToObject(o, "msg", e->msg);
        cJSON_AddItemToArray(a, o);
    }
    xSemaphoreGive(s_lock);
    return a;
}
