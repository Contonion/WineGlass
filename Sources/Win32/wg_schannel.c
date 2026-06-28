#include "wg_schannel.h"
#include "wg_log.h"
#include "wg_blink_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#pragma clang diagnostic pop

#define TAG "Schannel"

// ── SSPI / Schannel constants ──────────────────────────────────────
#define SEC_E_OK                    0x00000000
#define SEC_I_CONTINUE_NEEDED       0x00090312
#define SEC_E_INCOMPLETE_MESSAGE    0x80090318
#define SEC_E_INTERNAL_ERROR        0x80090304
#define SEC_I_CONTEXT_EXPIRED       0x00090317

#define SECBUFFER_EMPTY             0
#define SECBUFFER_DATA              1
#define SECBUFFER_TOKEN             2
#define SECBUFFER_EXTRA             5
#define SECBUFFER_STREAM_HEADER     7
#define SECBUFFER_STREAM_TRAILER    6
#define SECBUFFER_ALERT             17

#define SECPKG_ATTR_STREAM_SIZES    4

#define ISC_REQ_ALLOCATE_MEMORY     0x00000100
#define ISC_RET_ALLOCATED_MEMORY    0x00000100

// ── TLS context table ──────────────────────────────────────────────
#define WG_MAX_TLS 16

typedef struct {
    bool           active;
    SSLContextRef  ssl;
    int            fd;
    // Buffered IO for SSPI ↔ SecureTransport bridge
    uint8_t       *in_buf;
    size_t         in_len;
    size_t         in_pos;
    uint8_t       *out_buf;
    size_t         out_len;
    size_t         out_cap;
    bool           handshake_done;
    // Fake handles for Win32
    uint64_t       cred_handle;
    uint64_t       ctx_handle;
} WGTlsCtx;

struct WGSchannel {
    WGTlsCtx    ctx[WG_MAX_TLS];
    uint32_t     next_handle;
};

// ── Create / Destroy ───────────────────────────────────────────────

WGSchannel *wg_schannel_create(void) {
    WGSchannel *sc = calloc(1, sizeof(WGSchannel));
    if (!sc) return NULL;
    sc->next_handle = 0x9000;
    for (int i = 0; i < WG_MAX_TLS; i++)
        sc->ctx[i].fd = -1;
    return sc;
}

void wg_schannel_destroy(WGSchannel *sc) {
    if (!sc) return;
    for (int i = 0; i < WG_MAX_TLS; i++) {
        if (sc->ctx[i].ssl) { SSLClose(sc->ctx[i].ssl); CFRelease(sc->ctx[i].ssl); }
        free(sc->ctx[i].in_buf);
        free(sc->ctx[i].out_buf);
    }
    free(sc);
}

// ── IO callbacks — buffer-based, not socket-based ──────────────────

static OSStatus buf_read_cb(SSLConnectionRef conn, void *data, size_t *len) {
    WGTlsCtx *c = (WGTlsCtx *)conn;
    // Always read from in_buf — SSPI caller populates it (both handshake and DecryptMessage).
    size_t avail = c->in_len - c->in_pos;
    if (avail == 0) { *len = 0; return errSSLWouldBlock; }
    size_t copy = *len < avail ? *len : avail;
    memcpy(data, c->in_buf + c->in_pos, copy);
    c->in_pos += copy;
    *len = copy;
    return noErr;
}

static OSStatus buf_write_cb(SSLConnectionRef conn, const void *data, size_t *len) {
    WGTlsCtx *c = (WGTlsCtx *)conn;
    // Always capture to out_buf — SSPI caller reads it (both handshake and EncryptMessage).
    size_t need = c->out_len + *len;
    if (need > c->out_cap) {
        c->out_cap = need < 8192 ? 8192 : need * 2;
        c->out_buf = realloc(c->out_buf, c->out_cap);
    }
    memcpy(c->out_buf + c->out_len, data, *len);
    c->out_len += *len;
    return noErr;
}

// ── Helpers ────────────────────────────────────────────────────────

static WGTlsCtx *alloc_ctx(WGSchannel *sc) {
    for (int i = 0; i < WG_MAX_TLS; i++) {
        if (!sc->ctx[i].active) {
            memset(&sc->ctx[i], 0, sizeof(WGTlsCtx));
            sc->ctx[i].active = true;
            sc->ctx[i].fd = -1;
            return &sc->ctx[i];
        }
    }
    return NULL;
}

static WGTlsCtx *find_by_ctx_handle(WGSchannel *sc, uint64_t h) {
    for (int i = 0; i < WG_MAX_TLS; i++)
        if (sc->ctx[i].active && sc->ctx[i].ctx_handle == h)
            return &sc->ctx[i];
    return NULL;
}

static WGTlsCtx *find_by_fd(WGSchannel *sc, int fd) {
    for (int i = 0; i < WG_MAX_TLS; i++)
        if (sc->ctx[i].active && sc->ctx[i].fd == fd && sc->ctx[i].handshake_done)
            return &sc->ctx[i];
    return NULL;
}

// ── Read SecBuffer from guest memory ───────────────────────────────
// Win32 SecBuffer:  { cbBuffer(4), BufferType(4), pvBuffer(4) } = 12 bytes
// Win32 SecBufferDesc: { ulVersion(4), cBuffers(4), pBuffers(4) } = 12 bytes

static void read_sec_buffer(void *blink, uint32_t desc_ptr,
                            int idx, uint32_t *type, uint32_t *size, uint32_t *buf_ptr) {
    if (!desc_ptr) { *type = 0; *size = 0; *buf_ptr = 0; return; }
    uint32_t hdr[3];
    wg_blink_read_mem(blink, desc_ptr, hdr, 12);
    uint32_t count = hdr[1];
    uint32_t arr_ptr = hdr[2];
    if ((uint32_t)idx >= count || !arr_ptr) { *type = 0; *size = 0; *buf_ptr = 0; return; }
    uint32_t sb[3];
    wg_blink_read_mem(blink, arr_ptr + idx * 12, sb, 12);
    *size = sb[0];
    *type = sb[1];
    *buf_ptr = sb[2];
}

static void write_sec_buffer(void *blink, uint32_t desc_ptr,
                             int idx, uint32_t type, uint32_t size, uint32_t buf_ptr) {
    if (!desc_ptr) return;
    uint32_t hdr[3];
    wg_blink_read_mem(blink, desc_ptr, hdr, 12);
    uint32_t arr = hdr[2];
    if (!arr) return;
    uint32_t sb[3] = { size, type, buf_ptr };
    wg_blink_write_mem(blink, arr + idx * 12, sb, 12);
}

static uint32_t sec_buf_count(void *blink, uint32_t desc_ptr) {
    if (!desc_ptr) return 0;
    uint32_t hdr[3];
    wg_blink_read_mem(blink, desc_ptr, hdr, 12);
    return hdr[1];
}

// ── Handler ────────────────────────────────────────────────────────

bool wg_schannel_handle(WGSchannel *sc, const char *fn,
                        uint32_t *args, uint64_t *out_ret,
                        void *blink) {

    // ── InitSecurityInterfaceW ─────────────────────────────────────
    if (strcmp(fn, "InitSecurityInterfaceW") == 0 ||
        strcmp(fn, "InitSecurityInterfaceA") == 0) {
        // Return a fake function table pointer. Steam only uses this to get
        // function pointers which go through our thunk mechanism anyway.
        *out_ret = 0xBEEF0000;
        return true;
    }

    // ── AcquireCredentialsHandleW ──────────────────────────────────
    if (strcmp(fn, "AcquireCredentialsHandleW") == 0 ||
        strcmp(fn, "AcquireCredentialsHandleA") == 0) {
        // args: principal(0), package(1), usage(2), logonId(3), authData(4),
        //       getKeyFn(5), getKeyArg(6), phCredential(7), ptsExpiry(8)
        WGTlsCtx *c = alloc_ctx(sc);
        if (!c) { *out_ret = SEC_E_INTERNAL_ERROR; return true; }

        c->cred_handle = sc->next_handle++;

        // Write credential handle (2 x uint32 = SecHandle)
        if (args[7]) {
            uint32_t h[2] = { (uint32_t)c->cred_handle, 0 };
            wg_blink_write_mem(blink, args[7], h, 8);
        }
        // Write expiry (FILETIME = 8 bytes of 0 = never)
        if (args[8]) {
            uint64_t never = 0x7FFFFFFFFFFFFFFFULL;
            wg_blink_write_mem(blink, args[8], &never, 8);
        }

        WG_LOGI(TAG, "AcquireCredentialsHandle -> 0x%X", (uint32_t)c->cred_handle);
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── FreeCredentialsHandle ──────────────────────────────────────
    if (strcmp(fn, "FreeCredentialsHandle") == 0) {
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── InitializeSecurityContextW ─────────────────────────────────
    if (strcmp(fn, "InitializeSecurityContextW") == 0 ||
        strcmp(fn, "InitializeSecurityContextA") == 0) {
        // args: phCredential(0), phContext(1), pszTargetName(2), fContextReq(3),
        //       Reserved1(4), TargetDataRep(5), pInput(6), Reserved2(7),
        //       phNewContext(8), pOutput(9), pfContextAttr(10), ptsExpiry(11)
        uint32_t cred_ptr = args[0];
        uint32_t ctx_in_ptr = args[1];
        uint32_t target_ptr = args[2];
        uint32_t input_desc = args[6];
        uint32_t ctx_out_ptr = args[8];
        uint32_t output_desc = args[9];

        // Read target hostname
        char hostname[256] = {0};
        if (target_ptr) {
            uint16_t whost[256] = {0};
            wg_blink_read_mem(blink, target_ptr, whost, 510);
            for (int i = 0; i < 255 && whost[i]; i++)
                hostname[i] = whost[i] < 128 ? (char)whost[i] : '?';
        }

        // Find or create context
        WGTlsCtx *c = NULL;
        if (ctx_in_ptr) {
            uint32_t ch[2];
            wg_blink_read_mem(blink, ctx_in_ptr, ch, 8);
            c = find_by_ctx_handle(sc, ch[0]);
        }

        if (!c) {
            // First call — create new SSL context
            if (cred_ptr) {
                uint32_t ch[2];
                wg_blink_read_mem(blink, cred_ptr, ch, 8);
                for (int i = 0; i < WG_MAX_TLS; i++) {
                    if (sc->ctx[i].active && sc->ctx[i].cred_handle == ch[0]) {
                        c = &sc->ctx[i];
                        break;
                    }
                }
            }
            if (!c) c = alloc_ctx(sc);
            if (!c) { *out_ret = SEC_E_INTERNAL_ERROR; return true; }

            c->ctx_handle = sc->next_handle++;

            SSLContextRef ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
            if (!ssl) { *out_ret = SEC_E_INTERNAL_ERROR; return true; }
            SSLSetIOFuncs(ssl, buf_read_cb, buf_write_cb);
            SSLSetConnection(ssl, (SSLConnectionRef)c);
            if (hostname[0])
                SSLSetPeerDomainName(ssl, hostname, strlen(hostname));
            c->ssl = ssl;

            WG_LOGI(TAG, "InitializeSecurityContext: new ctx 0x%X host='%s'",
                    (uint32_t)c->ctx_handle, hostname);
        }

        // Feed input token to SecureTransport
        if (input_desc) {
            uint32_t bcount = sec_buf_count(blink, input_desc);
            for (uint32_t bi = 0; bi < bcount; bi++) {
                uint32_t btype, bsize, bptr;
                read_sec_buffer(blink, input_desc, bi, &btype, &bsize, &bptr);
                if (btype == SECBUFFER_TOKEN && bsize > 0 && bptr) {
                    free(c->in_buf);
                    c->in_buf = malloc(bsize);
                    wg_blink_read_mem(blink, bptr, c->in_buf, bsize);
                    c->in_len = bsize;
                    c->in_pos = 0;
                }
            }
        }

        // Clear output buffer
        c->out_len = 0;

        // Attempt handshake step
        OSStatus st = SSLHandshake(c->ssl);

        // Write output token
        if (output_desc && c->out_len > 0) {
            uint32_t bcount = sec_buf_count(blink, output_desc);
            for (uint32_t bi = 0; bi < bcount; bi++) {
                uint32_t btype, bsize, bptr;
                read_sec_buffer(blink, output_desc, bi, &btype, &bsize, &bptr);
                if ((btype == SECBUFFER_TOKEN || btype == SECBUFFER_EMPTY) && bptr && bsize >= (uint32_t)c->out_len) {
                    wg_blink_write_mem(blink, bptr, c->out_buf, (uint32_t)c->out_len);
                    write_sec_buffer(blink, output_desc, bi, SECBUFFER_TOKEN, (uint32_t)c->out_len, bptr);
                    break;
                }
            }
        }

        // Write context handle
        if (ctx_out_ptr) {
            uint32_t ch[2] = { (uint32_t)c->ctx_handle, 0 };
            wg_blink_write_mem(blink, ctx_out_ptr, ch, 8);
        }
        // Write context attributes
        if (args[10]) {
            uint32_t attr = args[3]; // echo back requested flags
            wg_blink_write_mem(blink, args[10], &attr, 4);
        }

        if (st == noErr) {
            c->handshake_done = true;
            WG_LOGI(TAG, "TLS handshake complete for ctx 0x%X", (uint32_t)c->ctx_handle);
            *out_ret = SEC_E_OK;
        } else if (st == errSSLWouldBlock) {
            WG_LOGD(TAG, "TLS handshake continue (sent %zu bytes)", c->out_len);
            *out_ret = SEC_I_CONTINUE_NEEDED;
        } else {
            WG_LOGE(TAG, "TLS handshake failed: %d", (int)st);
            *out_ret = SEC_E_INTERNAL_ERROR;
        }
        return true;
    }

    // ── DeleteSecurityContext ──────────────────────────────────────
    if (strcmp(fn, "DeleteSecurityContext") == 0) {
        if (args[0]) {
            uint32_t ch[2];
            wg_blink_read_mem(blink, args[0], ch, 8);
            WGTlsCtx *c = find_by_ctx_handle(sc, ch[0]);
            if (c) {
                if (c->ssl) { SSLClose(c->ssl); CFRelease(c->ssl); c->ssl = NULL; }
                free(c->in_buf); c->in_buf = NULL;
                free(c->out_buf); c->out_buf = NULL;
                c->active = false;
                c->fd = -1;
            }
        }
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── FreeContextBuffer ─────────────────────────────────────────
    if (strcmp(fn, "FreeContextBuffer") == 0) {
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── QueryContextAttributesW ───────────────────────────────────
    if (strcmp(fn, "QueryContextAttributesW") == 0 ||
        strcmp(fn, "QueryContextAttributesA") == 0) {
        uint32_t attr = args[1];
        if (attr == SECPKG_ATTR_STREAM_SIZES && args[2]) {
            // SecPkgContext_StreamSizes: header(4), trailer(4), maxMessage(4),
            // cBuffers(4), cbBlockSize(4)
            uint32_t sizes[5] = { 5, 36, 16384, 4, 16 };
            wg_blink_write_mem(blink, args[2], sizes, 20);
        }
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── EncryptMessage ────────────────────────────────────────────
    if (strcmp(fn, "EncryptMessage") == 0) {
        // args: phContext(0), fQOP(1), pMessage(2), MessageSeqNo(3)
        if (!args[0]) { *out_ret = SEC_E_INTERNAL_ERROR; return true; }
        uint32_t ch[2];
        wg_blink_read_mem(blink, args[0], ch, 8);
        WGTlsCtx *c = find_by_ctx_handle(sc, ch[0]);
        if (!c || !c->ssl || !c->handshake_done) {
            *out_ret = SEC_E_INTERNAL_ERROR;
            return true;
        }

        uint32_t msg_desc = args[2];
        uint32_t bcount = sec_buf_count(blink, msg_desc);

        // Find the DATA buffer (plaintext to encrypt)
        uint32_t data_ptr = 0, data_size = 0;
        int data_idx = -1;
        uint32_t hdr_ptr = 0, hdr_size = 0;
        int hdr_idx = -1;
        uint32_t trl_ptr = 0, trl_size = 0;
        int trl_idx = -1;

        for (uint32_t bi = 0; bi < bcount; bi++) {
            uint32_t btype, bsize, bptr;
            read_sec_buffer(blink, msg_desc, bi, &btype, &bsize, &bptr);
            if (btype == SECBUFFER_DATA) { data_ptr = bptr; data_size = bsize; data_idx = (int)bi; }
            else if (btype == SECBUFFER_STREAM_HEADER) { hdr_ptr = bptr; hdr_size = bsize; hdr_idx = (int)bi; }
            else if (btype == SECBUFFER_STREAM_TRAILER) { trl_ptr = bptr; trl_size = bsize; trl_idx = (int)bi; }
        }

        if (!data_ptr || data_size == 0) {
            *out_ret = SEC_E_INTERNAL_ERROR;
            return true;
        }

        // Read plaintext
        uint8_t *plain = malloc(data_size);
        wg_blink_read_mem(blink, data_ptr, plain, data_size);

        // SSLWrite encrypts and sends via write_cb → captures in out_buf
        c->out_len = 0;
        if (!c->out_buf) { c->out_cap = data_size + 256; c->out_buf = malloc(c->out_cap); }
        size_t processed = 0;
        OSStatus st = SSLWrite(c->ssl, plain, data_size, &processed);
        free(plain);

        if (st != noErr && processed == 0) {
            *out_ret = SEC_E_INTERNAL_ERROR;
            return true;
        }

        // The encrypted TLS record is in c->out_buf. Distribute it across the
        // header/data/trailer SecBuffers. The simplest approach: put everything
        // in the data buffer (Schannel-compatible apps handle this).
        if (c->out_len > 0) {
            // Put TLS header (first 5 bytes) in header buffer if available
            size_t pos = 0;
            if (hdr_idx >= 0 && hdr_ptr && hdr_size >= 5 && c->out_len >= 5) {
                wg_blink_write_mem(blink, hdr_ptr, c->out_buf, 5);
                write_sec_buffer(blink, msg_desc, hdr_idx, SECBUFFER_STREAM_HEADER, 5, hdr_ptr);
                pos = 5;
            }
            // Put encrypted payload in data buffer
            size_t payload = c->out_len - pos;
            if (trl_idx >= 0 && payload > 0) {
                // Reserve some for trailer
                size_t trl_actual = payload > 32 ? 32 : 0;
                size_t data_actual = payload - trl_actual;
                if (data_actual > 0 && data_ptr) {
                    uint32_t wlen = data_actual > data_size ? data_size : (uint32_t)data_actual;
                    wg_blink_write_mem(blink, data_ptr, c->out_buf + pos, wlen);
                    write_sec_buffer(blink, msg_desc, data_idx, SECBUFFER_DATA, wlen, data_ptr);
                    pos += wlen;
                }
                if (trl_actual > 0 && trl_ptr && trl_size >= (uint32_t)trl_actual) {
                    wg_blink_write_mem(blink, trl_ptr, c->out_buf + pos, (uint32_t)trl_actual);
                    write_sec_buffer(blink, msg_desc, trl_idx, SECBUFFER_STREAM_TRAILER, (uint32_t)trl_actual, trl_ptr);
                }
            } else if (data_ptr && payload > 0) {
                uint32_t wlen = payload > data_size ? data_size : (uint32_t)payload;
                wg_blink_write_mem(blink, data_ptr, c->out_buf + pos, wlen);
                write_sec_buffer(blink, msg_desc, data_idx, SECBUFFER_DATA, wlen, data_ptr);
            }
        }

        *out_ret = SEC_E_OK;
        return true;
    }

    // ── DecryptMessage ────────────────────────────────────────────
    if (strcmp(fn, "DecryptMessage") == 0) {
        // args: phContext(0), pMessage(1), MessageSeqNo(2), pfQOP(3)
        if (!args[0]) { *out_ret = SEC_E_INTERNAL_ERROR; return true; }
        uint32_t ch[2];
        wg_blink_read_mem(blink, args[0], ch, 8);
        WGTlsCtx *c = find_by_ctx_handle(sc, ch[0]);
        if (!c || !c->ssl || !c->handshake_done) {
            *out_ret = SEC_E_INTERNAL_ERROR;
            return true;
        }

        uint32_t msg_desc = args[1];
        uint32_t bcount = sec_buf_count(blink, msg_desc);

        // Find the DATA buffer (ciphertext)
        uint32_t data_ptr = 0, data_size = 0;
        int data_idx = -1;
        for (uint32_t bi = 0; bi < bcount; bi++) {
            uint32_t btype, bsize, bptr;
            read_sec_buffer(blink, msg_desc, bi, &btype, &bsize, &bptr);
            if (btype == SECBUFFER_DATA && bsize > 0) {
                data_ptr = bptr; data_size = bsize; data_idx = (int)bi;
                break;
            }
        }

        if (!data_ptr || data_size == 0) {
            *out_ret = SEC_E_INTERNAL_ERROR;
            return true;
        }

        // Feed ciphertext to SecureTransport
        free(c->in_buf);
        c->in_buf = malloc(data_size);
        wg_blink_read_mem(blink, data_ptr, c->in_buf, data_size);
        c->in_len = data_size;
        c->in_pos = 0;

        // SSLRead decrypts
        uint8_t *plain = malloc(data_size);
        size_t processed = 0;
        OSStatus st = SSLRead(c->ssl, plain, data_size, &processed);

        if (processed > 0) {
            // Write decrypted data back into the DATA buffer
            wg_blink_write_mem(blink, data_ptr, plain, (uint32_t)processed);
            write_sec_buffer(blink, msg_desc, data_idx, SECBUFFER_DATA, (uint32_t)processed, data_ptr);

            // Mark remaining buffers as empty, set one as EXTRA if there's leftover
            size_t leftover = c->in_len - c->in_pos;
            bool set_extra = false;
            for (uint32_t bi = 0; bi < bcount; bi++) {
                if ((int)bi == data_idx) continue;
                uint32_t btype, bsize, bptr;
                read_sec_buffer(blink, msg_desc, bi, &btype, &bsize, &bptr);
                if (!set_extra && leftover > 0) {
                    // There's leftover encrypted data
                    write_sec_buffer(blink, msg_desc, bi, SECBUFFER_EXTRA, (uint32_t)leftover, bptr);
                    set_extra = true;
                } else {
                    write_sec_buffer(blink, msg_desc, bi, SECBUFFER_EMPTY, 0, 0);
                }
            }
            free(plain);
            *out_ret = SEC_E_OK;
        } else if (st == errSSLClosedGraceful) {
            free(plain);
            *out_ret = SEC_I_CONTEXT_EXPIRED;
        } else {
            free(plain);
            *out_ret = SEC_E_INCOMPLETE_MESSAGE;
        }
        return true;
    }

    // ── CompleteAuthToken ─────────────────────────────────────────
    if (strcmp(fn, "CompleteAuthToken") == 0) {
        *out_ret = SEC_E_OK;
        return true;
    }

    // ── ApplyControlToken ─────────────────────────────────────────
    if (strcmp(fn, "ApplyControlToken") == 0) {
        *out_ret = SEC_E_OK;
        return true;
    }

    return false;
}

// ── Socket-level TLS operations ────────────────────────────────────

void wg_schannel_bind_fd(WGSchannel *sc, uint64_t ctx_handle, int fd) {
    WGTlsCtx *c = find_by_ctx_handle(sc, ctx_handle);
    if (c) c->fd = fd;
}

bool wg_schannel_has_tls(WGSchannel *sc, int fd) {
    return find_by_fd(sc, fd) != NULL;
}

ssize_t wg_schannel_send(WGSchannel *sc, int fd, const void *buf, size_t len) {
    WGTlsCtx *c = find_by_fd(sc, fd);
    if (!c || !c->ssl) return -1;
    size_t processed = 0;
    OSStatus st = SSLWrite(c->ssl, buf, len, &processed);
    if (st == noErr || processed > 0) return (ssize_t)processed;
    return -1;
}

ssize_t wg_schannel_recv(WGSchannel *sc, int fd, void *buf, size_t len) {
    WGTlsCtx *c = find_by_fd(sc, fd);
    if (!c || !c->ssl) return -1;
    size_t processed = 0;
    OSStatus st = SSLRead(c->ssl, buf, len, &processed);
    if (processed > 0) return (ssize_t)processed;
    if (st == errSSLClosedGraceful) return 0;
    return -1;
}
