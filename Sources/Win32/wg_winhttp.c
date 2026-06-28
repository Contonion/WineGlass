#include "wg_winhttp.h"
#include "wg_log.h"
#include "wg_blink_bridge.h"

#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/Security.h>
#include <Security/SecureTransport.h>
#pragma clang diagnostic pop

#define TAG "WinHTTP"

// ── WinHTTP constants ──────────────────────────────────────────────
#define WINHTTP_FLAG_SECURE             0x00800000
#define WINHTTP_QUERY_STATUS_CODE       19
#define WINHTTP_QUERY_STATUS_TEXT       20
#define WINHTTP_QUERY_CONTENT_LENGTH    5
#define WINHTTP_QUERY_RAW_HEADERS_CRLF  22
#define WINHTTP_QUERY_CUSTOM            65535
#define WINHTTP_QUERY_FLAG_NUMBER       0x20000000
#define WINHTTP_ADDREQ_FLAG_ADD         0x20000000
#define WINHTTP_ADDREQ_FLAG_REPLACE     0x80000000

#define ERROR_INSUFFICIENT_BUFFER       122
#define ERROR_WINHTTP_HEADER_NOT_FOUND  12150
#define ERROR_WINHTTP_CANNOT_CONNECT    12029
#define ERROR_WINHTTP_NAME_NOT_RESOLVED 12007
#define ERROR_WINHTTP_SECURE_FAILURE    12175

#define INTERNET_SCHEME_HTTP            1
#define INTERNET_SCHEME_HTTPS           2
#define INTERNET_DEFAULT_HTTP_PORT      80
#define INTERNET_DEFAULT_HTTPS_PORT     443

// ── Handle table ───────────────────────────────────────────────────
#define WG_MAX_HTTP  16
#define HTTP_BASE    0x3000u

enum { HT_NONE = 0, HT_SESSION, HT_CONNECT, HT_REQUEST };

typedef struct {
    int  type;
    bool in_use;

    // HT_SESSION
    char agent[256];

    // HT_CONNECT
    uint32_t session_h;
    char     server[512];
    uint16_t port;

    // HT_REQUEST
    uint32_t connect_h;
    char     verb[16];
    char     path[4096];
    char     extra_headers[8192];
    size_t   extra_headers_len;
    bool     use_ssl;
    int      fd;
    SSLContextRef ssl_ctx;

    int    status_code;
    char   status_text[128];
    char   resp_headers[16384];
    size_t resp_headers_len;
    uint8_t *buf;
    size_t buf_len;
    size_t buf_pos;
    size_t content_length;
    bool   has_content_length;
    bool   headers_received;
    size_t total_body_read;
} WGHttpSlot;

struct WGWinHttp {
    WGHttpSlot slots[WG_MAX_HTTP];
    uint32_t   last_error;
};

// ── Create / Destroy ───────────────────────────────────────────────

WGWinHttp *wg_winhttp_create(void) {
    WGWinHttp *wh = calloc(1, sizeof(WGWinHttp));
    if (!wh) return NULL;
    for (int i = 0; i < WG_MAX_HTTP; i++)
        wh->slots[i].fd = -1;
    return wh;
}

void wg_winhttp_destroy(WGWinHttp *wh) {
    if (!wh) return;
    for (int i = 0; i < WG_MAX_HTTP; i++) {
        WGHttpSlot *s = &wh->slots[i];
        if (s->ssl_ctx) { SSLClose(s->ssl_ctx); CFRelease(s->ssl_ctx); }
        if (s->fd >= 0) close(s->fd);
        free(s->buf);
    }
    free(wh);
}

// ── Handle management ──────────────────────────────────────────────

static uint32_t alloc_handle(WGWinHttp *wh, int type) {
    for (int i = 0; i < WG_MAX_HTTP; i++) {
        if (!wh->slots[i].in_use) {
            memset(&wh->slots[i], 0, sizeof(WGHttpSlot));
            wh->slots[i].in_use = true;
            wh->slots[i].type = type;
            wh->slots[i].fd = -1;
            return HTTP_BASE + (uint32_t)i;
        }
    }
    return 0;
}

static WGHttpSlot *get_slot(WGWinHttp *wh, uint32_t h) {
    if (h < HTTP_BASE || h >= HTTP_BASE + WG_MAX_HTTP) return NULL;
    WGHttpSlot *s = &wh->slots[h - HTTP_BASE];
    return s->in_use ? s : NULL;
}

static void free_handle(WGWinHttp *wh, uint32_t h) {
    WGHttpSlot *s = get_slot(wh, h);
    if (!s) return;
    if (s->ssl_ctx) { SSLClose(s->ssl_ctx); CFRelease(s->ssl_ctx); s->ssl_ctx = NULL; }
    if (s->fd >= 0) { close(s->fd); s->fd = -1; }
    free(s->buf); s->buf = NULL;
    s->in_use = false;
    s->type = HT_NONE;
}

// ── Wide-string helpers ────────────────────────────────────────────

static void read_wstr(void *blink, uint32_t ptr, char *out, int max) {
    out[0] = '\0';
    if (!ptr) return;
    int rlen = max < 2048 ? max : 2048;
    uint16_t wbuf[2048];
    wg_blink_read_mem(blink, ptr, wbuf, (uint32_t)(rlen * 2));
    int i;
    for (i = 0; i < rlen - 1 && wbuf[i]; i++)
        out[i] = wbuf[i] < 128 ? (char)wbuf[i] : '?';
    out[i] = '\0';
}

static void write_wstr_to(void *blink, uint32_t ptr, const char *str, int max_chars) {
    if (!ptr || !str) return;
    int len = (int)strlen(str);
    if (len >= max_chars) len = max_chars - 1;
    uint16_t wbuf[2048];
    int wlen = len < 2047 ? len : 2047;
    for (int i = 0; i < wlen; i++) wbuf[i] = (uint16_t)(unsigned char)str[i];
    wbuf[wlen] = 0;
    wg_blink_write_mem(blink, ptr, wbuf, (uint32_t)((wlen + 1) * 2));
}

// ── TLS callbacks (SecureTransport) ────────────────────────────────

static OSStatus ssl_read_cb(SSLConnectionRef conn, void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    ssize_t r = read(fd, data, *len);
    if (r > 0) { *len = (size_t)r; return noErr; }
    if (r == 0) { *len = 0; return errSSLClosedGraceful; }
    *len = 0;
    return (errno == EWOULDBLOCK || errno == EAGAIN) ? errSSLWouldBlock : errSecIO;
}

static OSStatus ssl_write_cb(SSLConnectionRef conn, const void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    ssize_t total = 0;
    while ((size_t)total < *len) {
        ssize_t w = write(fd, (const uint8_t *)data + total, *len - total);
        if (w > 0) { total += w; continue; }
        if (errno == EINTR) continue;
        *len = (size_t)total;
        return (errno == EWOULDBLOCK || errno == EAGAIN) ? errSSLWouldBlock : errSecIO;
    }
    *len = (size_t)total;
    return noErr;
}

// ── Socket I/O through optional TLS ────────────────────────────────

static ssize_t slot_read(WGHttpSlot *s, void *data, size_t len) {
    if (s->ssl_ctx) {
        size_t processed = 0;
        OSStatus st = SSLRead(s->ssl_ctx, data, len, &processed);
        if (processed > 0) return (ssize_t)processed;
        if (st == errSSLClosedGraceful || st == errSSLClosedAbort) return 0;
        return -1;
    }
    return read(s->fd, data, len);
}

static bool slot_write_all(WGHttpSlot *s, const void *data, size_t len) {
    const uint8_t *p = data;
    while (len > 0) {
        if (s->ssl_ctx) {
            size_t processed = 0;
            OSStatus st = SSLWrite(s->ssl_ctx, p, len, &processed);
            if (st != noErr && processed == 0) return false;
            p += processed;
            len -= processed;
        } else {
            ssize_t w = write(s->fd, p, len);
            if (w <= 0) { if (errno == EINTR) continue; return false; }
            p += w;
            len -= (size_t)w;
        }
    }
    return true;
}

// ── HTTP helpers ───────────────────────────────────────────────────

static bool http_connect_to(WGHttpSlot *req, const char *host, uint16_t port, bool ssl) {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);

    WG_LOGI(TAG, "Connecting to %s:%u (ssl=%d)", host, port, ssl);

    if (getaddrinfo(host, port_str, &hints, &res) != 0) {
        WG_LOGE(TAG, "DNS failed for %s", host);
        return false;
    }

    int fd = socket(res->ai_family, SOCK_STREAM, 0);
    if (fd < 0) { freeaddrinfo(res); return false; }

    if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
        WG_LOGE(TAG, "TCP connect to %s:%u failed: %s", host, port, strerror(errno));
        close(fd);
        freeaddrinfo(res);
        return false;
    }
    freeaddrinfo(res);
    req->fd = fd;

    if (ssl) {
        SSLContextRef ctx = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
        if (!ctx) { close(fd); req->fd = -1; return false; }

        SSLSetIOFuncs(ctx, ssl_read_cb, ssl_write_cb);
        SSLSetConnection(ctx, (SSLConnectionRef)(intptr_t)fd);
        SSLSetPeerDomainName(ctx, host, strlen(host));

        OSStatus status;
        do { status = SSLHandshake(ctx); } while (status == errSSLWouldBlock);

        if (status != noErr) {
            WG_LOGE(TAG, "TLS handshake with %s failed: %d", host, (int)status);
            CFRelease(ctx);
            close(fd);
            req->fd = -1;
            return false;
        }

        WG_LOGI(TAG, "TLS handshake with %s succeeded", host);
        req->ssl_ctx = ctx;
        req->use_ssl = true;
    }
    return true;
}

static bool http_send_req(WGHttpSlot *req, const char *host,
                          const void *body, size_t body_len) {
    char hdr[16384];
    int n = snprintf(hdr, sizeof(hdr),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Connection: keep-alive\r\n"
        "Accept: */*\r\n",
        req->verb, req->path[0] ? req->path : "/", host);

    if (req->extra_headers_len > 0)
        n += snprintf(hdr + n, sizeof(hdr) - (size_t)n, "%s", req->extra_headers);

    if (body && body_len > 0)
        n += snprintf(hdr + n, sizeof(hdr) - (size_t)n, "Content-Length: %zu\r\n", body_len);

    n += snprintf(hdr + n, sizeof(hdr) - (size_t)n, "\r\n");

    WG_LOGI(TAG, ">> %s %s (host=%s)", req->verb, req->path, host);

    if (!slot_write_all(req, hdr, (size_t)n)) return false;
    if (body && body_len > 0)
        if (!slot_write_all(req, body, body_len)) return false;
    return true;
}

static bool http_receive_headers(WGHttpSlot *req) {
    char raw[32768];
    size_t pos = 0;

    while (pos < sizeof(raw) - 1) {
        ssize_t r = slot_read(req, raw + pos, sizeof(raw) - 1 - pos);
        if (r <= 0) {
            if (pos > 0) break;
            return false;
        }
        pos += (size_t)r;
        raw[pos] = '\0';

        char *end = strstr(raw, "\r\n\r\n");
        if (end) {
            end += 4;
            size_t hdr_len = (size_t)(end - raw);

            int major, minor;
            char stext[128] = {0};
            if (sscanf(raw, "HTTP/%d.%d %d %127[^\r\n]",
                       &major, &minor, &req->status_code, stext) < 3)
                return false;
            strncpy(req->status_text, stext, sizeof(req->status_text) - 1);

            size_t copy = hdr_len < sizeof(req->resp_headers) - 1
                          ? hdr_len : sizeof(req->resp_headers) - 1;
            memcpy(req->resp_headers, raw, copy);
            req->resp_headers[copy] = '\0';
            req->resp_headers_len = copy;

            const char *cl = strcasestr(raw, "\r\nContent-Length:");
            if (cl) {
                req->content_length = (size_t)atoll(cl + 17);
                req->has_content_length = true;
            }

            size_t extra = pos - hdr_len;
            if (extra > 0) {
                req->buf = malloc(extra);
                if (req->buf) {
                    memcpy(req->buf, end, extra);
                    req->buf_len = extra;
                }
            }

            req->headers_received = true;
            WG_LOGI(TAG, "<< %d %s (content-length=%s%zu)",
                    req->status_code, req->status_text,
                    req->has_content_length ? "" : "~", req->content_length);
            return true;
        }
    }
    return false;
}

static const char *find_header_value(const char *headers, const char *name) {
    size_t nlen = strlen(name);
    const char *p = headers;
    while ((p = strcasestr(p, name)) != NULL) {
        if (p == headers || *(p - 1) == '\n') {
            p += nlen;
            while (*p == ' ' || *p == '\t') p++;
            return p;
        }
        p += nlen;
    }
    return NULL;
}

// ── Handler ────────────────────────────────────────────────────────

bool wg_winhttp_handle(WGWinHttp *wh, const char *fn,
                       uint32_t *args, uint64_t *out_ret,
                       void *blink) {

    // ── WinHttpOpen(agent, accessType, proxy, proxyBypass, flags) ──
    if (strcmp(fn, "WinHttpOpen") == 0) {
        uint32_t h = alloc_handle(wh, HT_SESSION);
        if (!h) { *out_ret = 0; return true; }
        WGHttpSlot *s = get_slot(wh, h);
        read_wstr(blink, args[0], s->agent, sizeof(s->agent));
        WG_LOGI(TAG, "WinHttpOpen('%s') -> 0x%X", s->agent, h);
        *out_ret = h;
        return true;
    }

    // ── WinHttpConnect(session, server, port, reserved) ────────────
    if (strcmp(fn, "WinHttpConnect") == 0) {
        WGHttpSlot *sess = get_slot(wh, args[0]);
        if (!sess || sess->type != HT_SESSION) { *out_ret = 0; return true; }

        uint32_t h = alloc_handle(wh, HT_CONNECT);
        if (!h) { *out_ret = 0; return true; }
        WGHttpSlot *s = get_slot(wh, h);
        s->session_h = args[0];
        read_wstr(blink, args[1], s->server, sizeof(s->server));
        s->port = (uint16_t)args[2];
        WG_LOGI(TAG, "WinHttpConnect('%s':%u) -> 0x%X", s->server, s->port, h);
        *out_ret = h;
        return true;
    }

    // ── WinHttpOpenRequest(conn, verb, path, version, referrer, acceptTypes, flags)
    if (strcmp(fn, "WinHttpOpenRequest") == 0) {
        WGHttpSlot *conn = get_slot(wh, args[0]);
        if (!conn || conn->type != HT_CONNECT) { *out_ret = 0; return true; }

        uint32_t h = alloc_handle(wh, HT_REQUEST);
        if (!h) { *out_ret = 0; return true; }
        WGHttpSlot *s = get_slot(wh, h);
        s->connect_h = args[0];

        if (args[1]) read_wstr(blink, args[1], s->verb, sizeof(s->verb));
        else strcpy(s->verb, "GET");

        if (args[2]) read_wstr(blink, args[2], s->path, sizeof(s->path));
        else strcpy(s->path, "/");

        s->use_ssl = (args[6] & WINHTTP_FLAG_SECURE) != 0;

        WG_LOGI(TAG, "WinHttpOpenRequest(%s %s, ssl=%d) -> 0x%X",
                s->verb, s->path, s->use_ssl, h);
        *out_ret = h;
        return true;
    }

    // ── WinHttpSetOption(handle, option, buffer, bufferLength) ──────
    if (strcmp(fn, "WinHttpSetOption") == 0) {
        WG_LOGD(TAG, "WinHttpSetOption(0x%X, opt=%u, len=%u)",
                args[0], args[1], args[3]);
        *out_ret = 1; // TRUE
        return true;
    }

    // ── WinHttpSetTimeouts(handle, resolve, connect, send, receive) ─
    if (strcmp(fn, "WinHttpSetTimeouts") == 0) {
        WG_LOGD(TAG, "WinHttpSetTimeouts(0x%X, %d, %d, %d, %d)",
                args[0], args[1], args[2], args[3], args[4]);
        *out_ret = 1;
        return true;
    }

    // ── WinHttpAddRequestHeaders(req, headers, length, modifiers) ──
    if (strcmp(fn, "WinHttpAddRequestHeaders") == 0) {
        WGHttpSlot *s = get_slot(wh, args[0]);
        if (!s || s->type != HT_REQUEST) { *out_ret = 0; return true; }

        char hdrs[4096] = {0};
        read_wstr(blink, args[1], hdrs, sizeof(hdrs));
        size_t hlen = strlen(hdrs);
        if (s->extra_headers_len + hlen < sizeof(s->extra_headers) - 2) {
            memcpy(s->extra_headers + s->extra_headers_len, hdrs, hlen);
            s->extra_headers_len += hlen;
            if (hlen > 0 && hdrs[hlen - 1] != '\n') {
                s->extra_headers[s->extra_headers_len++] = '\r';
                s->extra_headers[s->extra_headers_len++] = '\n';
            }
            s->extra_headers[s->extra_headers_len] = '\0';
        }
        *out_ret = 1;
        return true;
    }

    // ── WinHttpSendRequest(req, headers, headersLen, optional,
    //                       optionalLen, totalLen, context) ──────────
    if (strcmp(fn, "WinHttpSendRequest") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST) { wh->last_error = ERROR_WINHTTP_CANNOT_CONNECT; *out_ret = 0; return true; }

        WGHttpSlot *conn = get_slot(wh, req->connect_h);
        if (!conn) { wh->last_error = ERROR_WINHTTP_CANNOT_CONNECT; *out_ret = 0; return true; }

        if (args[1] && args[2] != 0 && args[2] != 0xFFFFFFFF) {
            char hdrs[4096] = {0};
            read_wstr(blink, args[1], hdrs, sizeof(hdrs));
            size_t hlen = strlen(hdrs);
            if (req->extra_headers_len + hlen < sizeof(req->extra_headers) - 2) {
                memcpy(req->extra_headers + req->extra_headers_len, hdrs, hlen);
                req->extra_headers_len += hlen;
                if (hlen > 0 && hdrs[hlen - 1] != '\n') {
                    req->extra_headers[req->extra_headers_len++] = '\r';
                    req->extra_headers[req->extra_headers_len++] = '\n';
                }
                req->extra_headers[req->extra_headers_len] = '\0';
            }
        }

        uint16_t port = conn->port;
        if (port == 0) port = req->use_ssl ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT;

        if (!http_connect_to(req, conn->server, port, req->use_ssl)) {
            wh->last_error = ERROR_WINHTTP_CANNOT_CONNECT;
            *out_ret = 0;
            return true;
        }

        uint8_t *post_body = NULL;
        uint32_t post_len = args[4];
        if (args[3] && post_len > 0) {
            post_body = malloc(post_len);
            if (post_body)
                wg_blink_read_mem(blink, args[3], post_body, post_len);
        }

        bool ok = http_send_req(req, conn->server, post_body, post_len);
        free(post_body);

        if (!ok) {
            wh->last_error = ERROR_WINHTTP_CANNOT_CONNECT;
            *out_ret = 0;
            return true;
        }

        *out_ret = 1;
        return true;
    }

    // ── WinHttpReceiveResponse(req, reserved) ──────────────────────
    if (strcmp(fn, "WinHttpReceiveResponse") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST || req->fd < 0) {
            *out_ret = 0;
            return true;
        }

        if (!http_receive_headers(req)) {
            WG_LOGE(TAG, "Failed to receive HTTP headers");
            *out_ret = 0;
            return true;
        }

        // Handle redirects (301, 302, 303, 307, 308)
        int redirects = 0;
        while (redirects < 5 &&
               (req->status_code == 301 || req->status_code == 302 ||
                req->status_code == 303 || req->status_code == 307 ||
                req->status_code == 308)) {
            const char *loc = find_header_value(req->resp_headers, "Location:");
            if (!loc) break;

            char url[4096] = {0};
            int k = 0;
            while (loc[k] && loc[k] != '\r' && loc[k] != '\n' && k < (int)sizeof(url) - 1) {
                url[k] = loc[k]; k++;
            }
            url[k] = '\0';
            WG_LOGI(TAG, "Redirect %d -> %s", req->status_code, url);

            // Close current connection
            if (req->ssl_ctx) { SSLClose(req->ssl_ctx); CFRelease(req->ssl_ctx); req->ssl_ctx = NULL; }
            if (req->fd >= 0) { close(req->fd); req->fd = -1; }
            free(req->buf); req->buf = NULL;
            req->buf_len = 0; req->buf_pos = 0;
            req->headers_received = false;

            // Parse redirect URL
            char host[512] = {0};
            uint16_t port = 0;
            bool ssl = false;
            const char *path_start = NULL;

            if (strncasecmp(url, "https://", 8) == 0) {
                ssl = true; port = 443;
                const char *h = url + 8;
                const char *slash = strchr(h, '/');
                const char *colon = strchr(h, ':');
                if (colon && (!slash || colon < slash)) {
                    int hlen = (int)(colon - h);
                    if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, h, hlen); host[hlen] = '\0'; }
                    port = (uint16_t)atoi(colon + 1);
                } else if (slash) {
                    int hlen = (int)(slash - h);
                    if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, h, hlen); host[hlen] = '\0'; }
                } else {
                    strncpy(host, h, sizeof(host) - 1);
                }
                path_start = slash;
            } else if (strncasecmp(url, "http://", 7) == 0) {
                port = 80;
                const char *h = url + 7;
                const char *slash = strchr(h, '/');
                const char *colon = strchr(h, ':');
                if (colon && (!slash || colon < slash)) {
                    int hlen = (int)(colon - h);
                    if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, h, hlen); host[hlen] = '\0'; }
                    port = (uint16_t)atoi(colon + 1);
                } else if (slash) {
                    int hlen = (int)(slash - h);
                    if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, h, hlen); host[hlen] = '\0'; }
                } else {
                    strncpy(host, h, sizeof(host) - 1);
                }
                path_start = slash;
            } else if (url[0] == '/') {
                // Relative redirect — reuse current connection params
                WGHttpSlot *conn = get_slot(wh, req->connect_h);
                if (conn) {
                    strncpy(host, conn->server, sizeof(host) - 1);
                    port = conn->port ? conn->port : (req->use_ssl ? 443 : 80);
                    ssl = req->use_ssl;
                }
                path_start = url;
            }

            if (path_start && path_start[0])
                strncpy(req->path, path_start, sizeof(req->path) - 1);
            else
                strcpy(req->path, "/");

            req->use_ssl = ssl;
            req->status_code = 0;
            req->resp_headers[0] = '\0';
            req->resp_headers_len = 0;
            req->content_length = 0;
            req->has_content_length = false;
            req->total_body_read = 0;

            if (!host[0]) break;

            if (!http_connect_to(req, host, port, ssl)) break;
            if (!http_send_req(req, host, NULL, 0)) break;
            if (!http_receive_headers(req)) break;
            redirects++;
        }

        *out_ret = req->headers_received ? 1 : 0;
        return true;
    }

    // ── WinHttpQueryHeaders(req, infoLevel, name, buffer, bufLen, index)
    if (strcmp(fn, "WinHttpQueryHeaders") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST || !req->headers_received) {
            wh->last_error = ERROR_WINHTTP_HEADER_NOT_FOUND;
            *out_ret = 0;
            return true;
        }

        uint32_t info_level = args[1];
        uint32_t buf_ptr = args[3];
        uint32_t buflen_ptr = args[4];
        uint32_t query = info_level & 0x0000FFFF;
        bool as_number = (info_level & WINHTTP_QUERY_FLAG_NUMBER) != 0;

        if (query == WINHTTP_QUERY_STATUS_CODE) {
            if (as_number) {
                uint32_t avail = 0;
                if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
                if (avail < 4) {
                    uint32_t need = 4;
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                    *out_ret = 0;
                } else {
                    uint32_t code = (uint32_t)req->status_code;
                    if (buf_ptr) wg_blink_write_mem(blink, buf_ptr, &code, 4);
                    uint32_t wrote = 4;
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &wrote, 4);
                    *out_ret = 1;
                }
            } else {
                char tmp[16];
                snprintf(tmp, sizeof(tmp), "%d", req->status_code);
                uint32_t avail = 0;
                if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
                uint32_t need = (uint32_t)(strlen(tmp) + 1) * 2;
                if (avail < need) {
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                    *out_ret = 0;
                } else {
                    write_wstr_to(blink, buf_ptr, tmp, (int)(avail / 2));
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    *out_ret = 1;
                }
            }
            return true;
        }

        if (query == WINHTTP_QUERY_CONTENT_LENGTH) {
            if (!req->has_content_length) {
                wh->last_error = ERROR_WINHTTP_HEADER_NOT_FOUND;
                *out_ret = 0;
                return true;
            }
            if (as_number) {
                uint32_t avail = 0;
                if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
                if (avail < 4) {
                    uint32_t need = 4;
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                    *out_ret = 0;
                } else {
                    uint32_t cl = (uint32_t)req->content_length;
                    if (buf_ptr) wg_blink_write_mem(blink, buf_ptr, &cl, 4);
                    uint32_t wrote = 4;
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &wrote, 4);
                    *out_ret = 1;
                }
            } else {
                char tmp[32];
                snprintf(tmp, sizeof(tmp), "%zu", req->content_length);
                uint32_t avail = 0;
                if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
                uint32_t need = (uint32_t)(strlen(tmp) + 1) * 2;
                if (avail < need) {
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                    *out_ret = 0;
                } else {
                    write_wstr_to(blink, buf_ptr, tmp, (int)(avail / 2));
                    if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                    *out_ret = 1;
                }
            }
            return true;
        }

        if (query == WINHTTP_QUERY_RAW_HEADERS_CRLF) {
            uint32_t avail = 0;
            if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
            uint32_t need = (uint32_t)(req->resp_headers_len + 1) * 2;
            if (avail < need) {
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                *out_ret = 0;
            } else {
                write_wstr_to(blink, buf_ptr, req->resp_headers, (int)(avail / 2));
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                *out_ret = 1;
            }
            return true;
        }

        if (query == WINHTTP_QUERY_STATUS_TEXT) {
            uint32_t avail = 0;
            if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
            uint32_t need = (uint32_t)(strlen(req->status_text) + 1) * 2;
            if (avail < need) {
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                *out_ret = 0;
            } else {
                write_wstr_to(blink, buf_ptr, req->status_text, (int)(avail / 2));
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                *out_ret = 1;
            }
            return true;
        }

        if (query == WINHTTP_QUERY_CUSTOM && args[2]) {
            char hdr_name[256] = {0};
            read_wstr(blink, args[2], hdr_name, sizeof(hdr_name));
            size_t nlen = strlen(hdr_name);
            char search[260];
            snprintf(search, sizeof(search), "%s:", hdr_name);
            const char *val = find_header_value(req->resp_headers, search);
            if (!val) {
                wh->last_error = ERROR_WINHTTP_HEADER_NOT_FOUND;
                *out_ret = 0;
                return true;
            }
            char result[4096] = {0};
            int k = 0;
            while (val[k] && val[k] != '\r' && val[k] != '\n' && k < (int)sizeof(result) - 1) {
                result[k] = val[k]; k++;
            }
            result[k] = '\0';

            uint32_t avail = 0;
            if (buflen_ptr) wg_blink_read_mem(blink, buflen_ptr, &avail, 4);
            uint32_t need = (uint32_t)(strlen(result) + 1) * 2;
            if (avail < need) {
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                wh->last_error = ERROR_INSUFFICIENT_BUFFER;
                *out_ret = 0;
            } else {
                write_wstr_to(blink, buf_ptr, result, (int)(avail / 2));
                if (buflen_ptr) wg_blink_write_mem(blink, buflen_ptr, &need, 4);
                *out_ret = 1;
            }
            return true;
        }

        wh->last_error = ERROR_WINHTTP_HEADER_NOT_FOUND;
        *out_ret = 0;
        return true;
    }

    // ── WinHttpQueryDataAvailable(req, bytesAvailable) ─────────────
    if (strcmp(fn, "WinHttpQueryDataAvailable") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST || req->fd < 0) {
            if (args[1]) { uint32_t z = 0; wg_blink_write_mem(blink, args[1], &z, 4); }
            *out_ret = 1;
            return true;
        }

        size_t buffered = req->buf_len - req->buf_pos;
        if (buffered == 0 && req->fd >= 0) {
            if (req->has_content_length && req->total_body_read >= req->content_length) {
                // All content received
            } else {
                if (!req->buf) { req->buf = malloc(65536); req->buf_len = 0; req->buf_pos = 0; }
                else if (req->buf_pos > 0) {
                    size_t left = req->buf_len - req->buf_pos;
                    if (left > 0) memmove(req->buf, req->buf + req->buf_pos, left);
                    req->buf_len = left;
                    req->buf_pos = 0;
                }
                ssize_t r = slot_read(req, req->buf + req->buf_len, 65536 - req->buf_len);
                if (r > 0) req->buf_len += (size_t)r;
                buffered = req->buf_len - req->buf_pos;
            }
        }

        uint32_t avail = (uint32_t)buffered;
        if (args[1]) wg_blink_write_mem(blink, args[1], &avail, 4);
        WG_LOGD(TAG, "WinHttpQueryDataAvailable -> %u", avail);
        *out_ret = 1;
        return true;
    }

    // ── WinHttpReadData(req, buffer, toRead, bytesRead) ────────────
    if (strcmp(fn, "WinHttpReadData") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST) {
            if (args[3]) { uint32_t z = 0; wg_blink_write_mem(blink, args[3], &z, 4); }
            *out_ret = 0;
            return true;
        }

        uint32_t buf_ptr = args[1];
        uint32_t to_read = args[2];
        uint32_t read_ptr = args[3];
        uint32_t total_given = 0;

        // Serve from buffer first
        size_t buffered = req->buf_len - req->buf_pos;
        if (buffered > 0) {
            size_t give = buffered < to_read ? buffered : to_read;
            wg_blink_write_mem(blink, buf_ptr, req->buf + req->buf_pos, (uint32_t)give);
            req->buf_pos += give;
            total_given = (uint32_t)give;
            to_read -= (uint32_t)give;
            buf_ptr += (uint32_t)give;
        }

        // Read more from socket if needed
        if (to_read > 0 && req->fd >= 0) {
            size_t chunk = to_read < 65536 ? to_read : 65536;
            uint8_t *tmp = malloc(chunk);
            if (tmp) {
                ssize_t got = slot_read(req, tmp, chunk);
                if (got > 0) {
                    wg_blink_write_mem(blink, buf_ptr, tmp, (uint32_t)got);
                    total_given += (uint32_t)got;
                }
                free(tmp);
            }
        }

        req->total_body_read += total_given;
        if (read_ptr) wg_blink_write_mem(blink, read_ptr, &total_given, 4);
        WG_LOGD(TAG, "WinHttpReadData -> %u bytes", total_given);
        *out_ret = 1;
        return true;
    }

    // ── WinHttpWriteData(req, buffer, toWrite, bytesWritten) ───────
    if (strcmp(fn, "WinHttpWriteData") == 0) {
        WGHttpSlot *req = get_slot(wh, args[0]);
        if (!req || req->type != HT_REQUEST || req->fd < 0) {
            *out_ret = 0;
            return true;
        }

        uint32_t len = args[2];
        if (len > 0 && args[1]) {
            uint8_t *data = malloc(len);
            if (data) {
                wg_blink_read_mem(blink, args[1], data, len);
                bool ok = slot_write_all(req, data, len);
                free(data);
                if (!ok) { *out_ret = 0; return true; }
            }
        }
        if (args[3]) wg_blink_write_mem(blink, args[3], &len, 4);
        *out_ret = 1;
        return true;
    }

    // ── WinHttpCloseHandle(handle) ─────────────────────────────────
    if (strcmp(fn, "WinHttpCloseHandle") == 0) {
        WG_LOGD(TAG, "WinHttpCloseHandle(0x%X)", args[0]);
        free_handle(wh, args[0]);
        *out_ret = 1;
        return true;
    }

    // ── WinHttpSetStatusCallback ───────────────────────────────────
    if (strcmp(fn, "WinHttpSetStatusCallback") == 0) {
        WG_LOGD(TAG, "WinHttpSetStatusCallback(0x%X, cb=0x%X, flags=0x%X)",
                args[0], args[1], args[2]);
        *out_ret = 0; // NULL = no previous callback
        return true;
    }

    // ── WinHttpCrackUrl(url, urlLength, flags, components) ─────────
    if (strcmp(fn, "WinHttpCrackUrl") == 0) {
        char url[4096] = {0};
        uint32_t url_len = args[1];
        if (url_len == 0 || url_len > 4000) url_len = 4000;
        read_wstr(blink, args[0], url, (int)url_len + 1);
        WG_LOGI(TAG, "WinHttpCrackUrl('%s')", url);

        uint32_t comp_ptr = args[3];
        if (!comp_ptr) { *out_ret = 0; return true; }

        // Parse URL: scheme://host[:port]/path[?extra]
        const char *scheme = "http";
        int nscheme = INTERNET_SCHEME_HTTP;
        uint16_t port = 80;
        char host[512] = {0};
        char path[4096] = {0};
        char extra[2048] = {0};

        const char *p = url;
        if (strncasecmp(p, "https://", 8) == 0) {
            scheme = "https"; nscheme = INTERNET_SCHEME_HTTPS; port = 443; p += 8;
        } else if (strncasecmp(p, "http://", 7) == 0) {
            p += 7;
        }

        const char *slash = strchr(p, '/');
        const char *colon = strchr(p, ':');
        if (colon && (!slash || colon < slash)) {
            int hlen = (int)(colon - p);
            if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, p, hlen); host[hlen] = '\0'; }
            port = (uint16_t)atoi(colon + 1);
        } else if (slash) {
            int hlen = (int)(slash - p);
            if (hlen > 0 && hlen < (int)sizeof(host)) { memcpy(host, p, hlen); host[hlen] = '\0'; }
        } else {
            strncpy(host, p, sizeof(host) - 1);
        }

        if (slash) {
            const char *q = strchr(slash, '?');
            if (q) {
                int plen = (int)(q - slash);
                if (plen < (int)sizeof(path)) { memcpy(path, slash, plen); path[plen] = '\0'; }
                strncpy(extra, q, sizeof(extra) - 1);
            } else {
                strncpy(path, slash, sizeof(path) - 1);
            }
        } else {
            strcpy(path, "/");
        }

        // Read component struct to get buffer pointers and lengths
        // Layout (32-bit): dwStructSize(+0), lpszScheme(+4), dwSchemeLength(+8),
        // nScheme(+12), lpszHostName(+16), dwHostNameLength(+20),
        // nPort(+24, 2 bytes), pad(+26), lpszUserName(+28), dwUserNameLength(+32),
        // lpszPassword(+36), dwPasswordLength(+40), lpszUrlPath(+44),
        // dwUrlPathLength(+48), lpszExtraInfo(+52), dwExtraInfoLength(+56)
        uint8_t comp[60] = {0};
        wg_blink_read_mem(blink, comp_ptr, comp, 60);

        uint32_t scheme_ptr  = *(uint32_t *)(comp + 4);
        uint32_t scheme_len  = *(uint32_t *)(comp + 8);
        uint32_t host_ptr    = *(uint32_t *)(comp + 16);
        uint32_t host_len    = *(uint32_t *)(comp + 20);
        uint32_t path_ptr    = *(uint32_t *)(comp + 44);
        uint32_t path_len    = *(uint32_t *)(comp + 48);
        uint32_t extra_ptr   = *(uint32_t *)(comp + 52);
        uint32_t extra_len   = *(uint32_t *)(comp + 56);

        // Write nScheme
        uint32_t ns = (uint32_t)nscheme;
        wg_blink_write_mem(blink, comp_ptr + 12, &ns, 4);
        // Write nPort
        wg_blink_write_mem(blink, comp_ptr + 24, &port, 2);

        if (scheme_ptr && scheme_len > 0)
            write_wstr_to(blink, scheme_ptr, scheme, (int)scheme_len);
        if (scheme_len > 0) {
            uint32_t slen = (uint32_t)strlen(scheme);
            wg_blink_write_mem(blink, comp_ptr + 8, &slen, 4);
        }

        if (host_ptr && host_len > 0)
            write_wstr_to(blink, host_ptr, host, (int)host_len);
        if (host_len > 0) {
            uint32_t hlen = (uint32_t)strlen(host);
            wg_blink_write_mem(blink, comp_ptr + 20, &hlen, 4);
        }

        if (path_ptr && path_len > 0)
            write_wstr_to(blink, path_ptr, path, (int)path_len);
        if (path_len > 0) {
            uint32_t plen = (uint32_t)strlen(path);
            wg_blink_write_mem(blink, comp_ptr + 48, &plen, 4);
        }

        if (extra_ptr && extra_len > 0)
            write_wstr_to(blink, extra_ptr, extra, (int)extra_len);
        if (extra_len > 0) {
            uint32_t elen = (uint32_t)strlen(extra);
            wg_blink_write_mem(blink, comp_ptr + 56, &elen, 4);
        }

        *out_ret = 1;
        return true;
    }

    // ── WinHttpGetProxyForUrl ──────────────────────────────────────
    if (strcmp(fn, "WinHttpGetProxyForUrl") == 0) {
        *out_ret = 0; // no proxy
        return true;
    }

    // ── WinHttpGetDefaultProxyConfiguration ────────────────────────
    if (strcmp(fn, "WinHttpGetDefaultProxyConfiguration") == 0) {
        if (args[0]) {
            uint32_t proxy_info[3] = {0}; // WINHTTP_PROXY_INFO: accessType=1(direct), proxy=0, bypass=0
            proxy_info[0] = 1;
            wg_blink_write_mem(blink, args[0], proxy_info, 12);
        }
        *out_ret = 1;
        return true;
    }

    // ── WinHttpGetIEProxyConfigForCurrentUser ──────────────────────
    if (strcmp(fn, "WinHttpGetIEProxyConfigForCurrentUser") == 0) {
        if (args[0]) {
            uint32_t zero[4] = {0}; // fAutoDetect=0, autoConfigUrl=0, proxy=0, proxyBypass=0
            wg_blink_write_mem(blink, args[0], zero, 16);
        }
        *out_ret = 1;
        return true;
    }

    return false;
}
