// Shared helpers of the web server (web.c) and the REST API handlers (api.c).
#pragma once

#include "esp_http_server.h"
#include "app.h"

typedef struct {
    sp_identity_t id;
    bool cookie;            // authenticated by session cookie (CSRF header required for writes)
} web_auth_t;

// Authenticates the request; on failure the error response is already sent and false returned.
bool web_auth(httpd_req_t *req, bool admin, web_auth_t *a);
esp_err_t web_json(httpd_req_t *req, int status, cJSON *body);       // frees body
esp_err_t web_error(httpd_req_t *req, int status, const char *msg);
char *web_body(httpd_req_t *req, size_t max, size_t *len);           // caller frees, NUL terminated
bool web_query(httpd_req_t *req, const char *key, char *out, size_t outsz);
void web_peer(httpd_req_t *req, char *out, size_t outsz);
bool web_is_https(httpd_req_t *req);
void web_drop_sessions(const char *user);                             // after password change/delete

void api_register(httpd_handle_t h);
