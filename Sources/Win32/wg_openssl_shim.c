// wg_openssl_shim.c — SecureTransport-backed replacement for Steam's OpenSSL TLS.
// See wg_openssl_shim.h. Buffer model mirrors wg_schannel.c.

#include "wg_openssl_shim.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/SecureTransport.h>
#pragma clang diagnostic pop

#define TAG "OSSLShim"
#define WG_OSSL_MAX 16

typedef struct {
    bool         used;
    uint32_t     ssl;          // guest SSL*
    uint32_t     rbio, wbio;   // guest BIO*s
    char         host[256];
    SSLContextRef st;
    bool         handshaked;
    int          last_error;   // WG_SSL_ERROR_*
    // in_buf: ciphertext received from the network, consumed by SecureTransport.
    uint8_t     *in_buf; size_t in_len, in_pos, in_cap;
    // out_buf: ciphertext produced by SecureTransport, drained to the network.
    uint8_t     *out_buf; size_t out_len, out_pos, out_cap;
} WGOsslCtx;

static WGOsslCtx g_ctx[WG_OSSL_MAX];

static WGOsslCtx *find(uint32_t ssl) {
    for (int i = 0; i < WG_OSSL_MAX; i++)
        if (g_ctx[i].used && g_ctx[i].ssl == ssl) return &g_ctx[i];
    return NULL;
}
static WGOsslCtx *alloc_ctx(uint32_t ssl) {
    for (int i = 0; i < WG_OSSL_MAX; i++)
        if (!g_ctx[i].used) {
            memset(&g_ctx[i], 0, sizeof(WGOsslCtx));
            g_ctx[i].used = true; g_ctx[i].ssl = ssl;
            return &g_ctx[i];
        }
    return NULL;
}

// SecureTransport pulls received ciphertext from in_buf.
static OSStatus st_read(SSLConnectionRef conn, void *data, size_t *len) {
    WGOsslCtx *c = (WGOsslCtx *)conn;
    size_t want = *len, avail = c->in_len - c->in_pos;
    if (avail == 0) { *len = 0; return errSSLWouldBlock; }
    size_t copy = want < avail ? want : avail;
    memcpy(data, c->in_buf + c->in_pos, copy);
    c->in_pos += copy;
    *len = copy;
    return (copy < want) ? errSSLWouldBlock : noErr;
}
// SecureTransport pushes ciphertext-to-send into out_buf.
static OSStatus st_write(SSLConnectionRef conn, const void *data, size_t *len) {
    WGOsslCtx *c = (WGOsslCtx *)conn;
    if (c->out_len + *len > c->out_cap) {
        c->out_cap = (c->out_len + *len) * 2 + 1024;
        c->out_buf = realloc(c->out_buf, c->out_cap);
    }
    memcpy(c->out_buf + c->out_len, data, *len);
    c->out_len += *len;
    return noErr;
}

static void reset_in(WGOsslCtx *c) {
    // Compact: drop fully-consumed input.
    if (c->in_pos && c->in_pos == c->in_len) { c->in_len = c->in_pos = 0; }
}

void wg_ossl_attach(uint32_t ssl, uint32_t rbio, uint32_t wbio) {
    WGOsslCtx *c = find(ssl);
    if (!c) c = alloc_ctx(ssl);
    if (!c) { WG_LOGW(TAG, "no free shim slot for SSL 0x%X", ssl); return; }
    if (rbio) c->rbio = rbio;
    if (wbio) c->wbio = wbio;
    if (!c->st) {
        c->st = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
        SSLSetIOFuncs(c->st, st_read, st_write);
        SSLSetConnection(c->st, (SSLConnectionRef)c);
        if (c->host[0]) SSLSetPeerDomainName(c->st, c->host, strlen(c->host));
        WG_LOGI(TAG, "attach SSL=0x%X rbio=0x%X wbio=0x%X host='%s'", ssl, rbio, wbio, c->host);
    }
}

void wg_ossl_set_host(uint32_t ssl, const char *host) {
    WGOsslCtx *c = find(ssl);
    if (!c) c = alloc_ctx(ssl);
    if (!c || !host) return;
    strncpy(c->host, host, sizeof(c->host) - 1);
    if (c->st) SSLSetPeerDomainName(c->st, c->host, strlen(c->host));
}

void wg_ossl_free(uint32_t ssl) {
    WGOsslCtx *c = find(ssl);
    if (!c) return;
    if (c->st) { SSLClose(c->st); CFRelease(c->st); }
    free(c->in_buf); free(c->out_buf);
    memset(c, 0, sizeof(*c));
}

bool wg_ossl_known(uint32_t ssl) { return find(ssl) != NULL; }
bool wg_ossl_bio_is_rbio(uint32_t bio) {
    for (int i = 0; i < WG_OSSL_MAX; i++) if (g_ctx[i].used && g_ctx[i].rbio == bio) return true;
    return false;
}
bool wg_ossl_bio_is_wbio(uint32_t bio) {
    for (int i = 0; i < WG_OSSL_MAX; i++) if (g_ctx[i].used && g_ctx[i].wbio == bio) return true;
    return false;
}
uint32_t wg_ossl_ssl_for_bio(uint32_t bio) {
    for (int i = 0; i < WG_OSSL_MAX; i++)
        if (g_ctx[i].used && (g_ctx[i].rbio == bio || g_ctx[i].wbio == bio)) return g_ctx[i].ssl;
    return 0;
}

void wg_ossl_feed(uint32_t ssl, const uint8_t *cipher, uint32_t len) {
    WGOsslCtx *c = find(ssl);
    if (!c || !len) return;
    reset_in(c);
    if (c->in_len + len > c->in_cap) {
        c->in_cap = (c->in_len + len) * 2 + 4096;
        c->in_buf = realloc(c->in_buf, c->in_cap);
    }
    memcpy(c->in_buf + c->in_len, cipher, len);
    c->in_len += len;
}

uint32_t wg_ossl_pending_out(uint32_t ssl) {
    WGOsslCtx *c = find(ssl);
    return c ? (uint32_t)(c->out_len - c->out_pos) : 0;
}
uint32_t wg_ossl_drain(uint32_t ssl, uint8_t *out, uint32_t cap) {
    WGOsslCtx *c = find(ssl);
    if (!c) return 0;
    size_t avail = c->out_len - c->out_pos;
    size_t copy = cap < avail ? cap : avail;
    if (copy) memcpy(out, c->out_buf + c->out_pos, copy);
    c->out_pos += copy;
    if (c->out_pos == c->out_len) { c->out_len = c->out_pos = 0; }
    return (uint32_t)copy;
}

int wg_ossl_do_handshake(uint32_t ssl) {
    WGOsslCtx *c = find(ssl);
    if (!c || !c->st) return -1;
    OSStatus st = SSLHandshake(c->st);
    if (st == noErr) {
        c->handshaked = true;
        c->last_error = WG_SSL_ERROR_NONE;
        SSLProtocol proto = 0; SSLGetNegotiatedProtocolVersion(c->st, &proto);
        WG_LOGI(TAG, "SSL 0x%X handshake COMPLETE (proto=%d, %u bytes to send)",
                ssl, (int)proto, wg_ossl_pending_out(ssl));
        return 1;
    }
    if (st == errSSLWouldBlock) {
        // Need more network data (or have output to flush). WANT_WRITE if we have
        // pending ciphertext to send, else WANT_READ.
        c->last_error = wg_ossl_pending_out(ssl) ? WG_SSL_ERROR_WANT_WRITE
                                                 : WG_SSL_ERROR_WANT_READ;
        return -1;
    }
    WG_LOGW(TAG, "SSL 0x%X handshake error OSStatus=%d", ssl, (int)st);
    c->last_error = WG_SSL_ERROR_SSL;
    return -1;
}

int wg_ossl_get_error(uint32_t ssl) {
    WGOsslCtx *c = find(ssl);
    return c ? c->last_error : WG_SSL_ERROR_SSL;
}

int wg_ossl_write(uint32_t ssl, const uint8_t *plain, uint32_t len) {
    WGOsslCtx *c = find(ssl);
    if (!c || !c->st) return -1;
    size_t done = 0;
    OSStatus st = SSLWrite(c->st, plain, len, &done);
    if (st == noErr || (st == errSSLWouldBlock && done > 0)) {
        c->last_error = WG_SSL_ERROR_NONE;
        return (int)done;
    }
    c->last_error = (st == errSSLWouldBlock) ? WG_SSL_ERROR_WANT_WRITE : WG_SSL_ERROR_SSL;
    return -1;
}

int wg_ossl_read(uint32_t ssl, uint8_t *out, uint32_t cap) {
    WGOsslCtx *c = find(ssl);
    if (!c || !c->st) return -1;
    size_t done = 0;
    OSStatus st = SSLRead(c->st, out, cap, &done);
    if (done > 0) { c->last_error = WG_SSL_ERROR_NONE; return (int)done; }
    if (st == errSSLWouldBlock) { c->last_error = WG_SSL_ERROR_WANT_READ; return -1; }
    if (st == errSSLClosedGraceful) { c->last_error = WG_SSL_ERROR_ZERO_RETURN; return 0; }
    c->last_error = WG_SSL_ERROR_SSL;
    return -1;
}
