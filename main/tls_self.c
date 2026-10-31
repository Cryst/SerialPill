// Self-signed HTTPS certificate: generated on first boot (ECDSA P-256) so HTTPS works out of the
// box; replaced by an uploaded certificate, regenerated on request.
#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_netif.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/pk.h"
#include "mbedtls/ecp.h"
#include "mbedtls/oid.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "app.h"

static const char *TAG = "tls";

bool tls_is_selfsigned(void)
{
    void *d = NULL;
    size_t n = 0;
    bool r = config_blob_get("tls_self", &d, &n) == ESP_OK;
    free(d);
    return r;
}

static int add_san(mbedtls_x509_san_list *l, int type, const void *p, size_t len)
{
    l->node.type = type;
    l->node.san.unstructured_name.p = (unsigned char *)p;
    l->node.san.unstructured_name.len = len;
    return 0;
}

esp_err_t tls_selfsigned(bool force)
{
    void *d = NULL;
    size_t n = 0;
    if (!force && config_blob_get("tls_cert", &d, &n) == ESP_OK) { free(d); return ESP_OK; }
    free(d);

    char local[48], subject[96];
    snprintf(local, sizeof local, "%s.local", g_cfg.hostname);
    snprintf(subject, sizeof subject, "CN=%s,O=SerialPill", g_cfg.hostname);
    // SAN: hostname, hostname.local and the current IPv4 address (if any)
    mbedtls_x509_san_list san[3];
    memset(san, 0, sizeof san);
    add_san(&san[0], MBEDTLS_X509_SAN_DNS_NAME, g_cfg.hostname, strlen(g_cfg.hostname));
    add_san(&san[1], MBEDTLS_X509_SAN_DNS_NAME, local, strlen(local));
    san[0].next = &san[1];
    uint8_t ip[4];
    esp_netif_ip_info_t ii;
    esp_netif_t *nif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (nif && esp_netif_get_ip_info(nif, &ii) == ESP_OK && ii.ip.addr) {
        memcpy(ip, &ii.ip.addr, 4);
        add_san(&san[2], MBEDTLS_X509_SAN_IP_ADDRESS, ip, 4);
        san[1].next = &san[2];
    }

    mbedtls_pk_context key;
    mbedtls_x509write_cert crt;
    mbedtls_entropy_context ent;
    mbedtls_ctr_drbg_context drbg;
    mbedtls_pk_init(&key);
    mbedtls_x509write_crt_init(&crt);
    mbedtls_entropy_init(&ent);
    mbedtls_ctr_drbg_init(&drbg);
    unsigned char *cert_pem = malloc(2048), *key_pem = malloc(512);
    uint8_t serial[16];
    int r = (!cert_pem || !key_pem) ? -1 : 0;
    if (!r) r = mbedtls_ctr_drbg_seed(&drbg, mbedtls_entropy_func, &ent, (const unsigned char *)"sp-tls", 6);
    if (!r) r = mbedtls_pk_setup(&key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (!r) r = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, mbedtls_pk_ec(key), mbedtls_ctr_drbg_random, &drbg);
    if (!r) r = mbedtls_ctr_drbg_random(&drbg, serial, sizeof serial);
    if (!r) {
        serial[0] &= 0x7f;                      // positive
        serial[0] |= 0x40;
        mbedtls_x509write_crt_set_version(&crt, MBEDTLS_X509_CRT_VERSION_3);
        mbedtls_x509write_crt_set_md_alg(&crt, MBEDTLS_MD_SHA256);
        mbedtls_x509write_crt_set_subject_key(&crt, &key);
        mbedtls_x509write_crt_set_issuer_key(&crt, &key);
        r = mbedtls_x509write_crt_set_serial_raw(&crt, serial, sizeof serial);
    }
    if (!r) r = mbedtls_x509write_crt_set_subject_name(&crt, subject);
    if (!r) r = mbedtls_x509write_crt_set_issuer_name(&crt, subject);
    if (!r) r = mbedtls_x509write_crt_set_validity(&crt, "20250101000000", "20491231235959");
    if (!r) r = mbedtls_x509write_crt_set_basic_constraints(&crt, 0, -1);
    if (!r) r = mbedtls_x509write_crt_set_key_usage(&crt, MBEDTLS_X509_KU_DIGITAL_SIGNATURE | MBEDTLS_X509_KU_KEY_AGREEMENT);
    if (!r) {
        mbedtls_asn1_sequence eku = { .buf = { .tag = MBEDTLS_ASN1_OID, .len = MBEDTLS_OID_SIZE(MBEDTLS_OID_SERVER_AUTH),
                                              .p = (unsigned char *)MBEDTLS_OID_SERVER_AUTH } };
        r = mbedtls_x509write_crt_set_ext_key_usage(&crt, &eku);
    }
    if (!r) r = mbedtls_x509write_crt_set_subject_alternative_name(&crt, san);
    if (!r) r = mbedtls_x509write_crt_pem(&crt, cert_pem, 2048, mbedtls_ctr_drbg_random, &drbg);
    if (!r) r = mbedtls_pk_write_key_pem(&key, key_pem, 512);
    if (!r && (config_blob_set("tls_cert", cert_pem, strlen((char *)cert_pem)) ||
               config_blob_set("tls_key", key_pem, strlen((char *)key_pem)) ||
               config_blob_set("tls_self", "1", 1))) r = -2;
    if (key_pem) memset(key_pem, 0, 512);
    free(cert_pem);
    free(key_pem);
    mbedtls_x509write_crt_free(&crt);
    mbedtls_pk_free(&key);
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&ent);
    if (r) {
        ESP_LOGE(TAG, "self-signed certificate failed: -0x%04x", -r);
        audit("web: cannot create the self-signed certificate (%d)", r);
        return ESP_FAIL;
    }
    audit("web: self-signed HTTPS certificate created for %s", g_cfg.hostname);
    return ESP_OK;
}
