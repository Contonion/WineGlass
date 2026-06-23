#include "wg_winsock.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>

#define TAG "WSock"

// blink memory access (declared in wg_blink_bridge.h, but we only need
// read/write — keep the dependency light by declaring the two we use).
extern void wg_blink_read_mem(void *vm, uint64_t addr, void *buf, uint32_t len);
extern void wg_blink_write_mem(void *vm, uint64_t addr, const void *buf, uint32_t len);

// ── Windows socket constants ────────────────────────────────────────
#define WSADESCRIPTION_LEN  256
#define WSASYS_STATUS_LEN   128
#define WIN_INVALID_SOCKET  (~(uint32_t)0)
#define WIN_SOCKET_ERROR    (-1)
#define WIN_SD_RECEIVE      0
#define WIN_SD_SEND         1
#define WIN_SD_BOTH         2

// Winsock error codes
#define WSAEWOULDBLOCK    10035
#define WSAEINPROGRESS    10036
#define WSAEALREADY       10037
#define WSAENOTSOCK       10038
#define WSAECONNREFUSED   10061
#define WSAECONNRESET     10054
#define WSAECONNABORTED   10053
#define WSAETIMEDOUT      10060
#define WSAENETUNREACH    10051
#define WSAEHOSTUNREACH   10065
#define WSANOTINITIALISED 10093
#define WSAEINVAL         10022
#define WSAEMSGSIZE       10040
#define WSAENOTCONN       10057
#define WSAEAFNOSUPPORT   10047

// Windows AF/SOCK/IPPROTO match BSD values on most platforms
#define WIN_AF_INET       2
#define WIN_AF_INET6      23
#define WIN_SOCK_STREAM   1
#define WIN_SOCK_DGRAM    2

// FIONBIO for ioctlsocket
#define WIN_FIONBIO       0x8004667E
#define WIN_FIONREAD      0x4004667F

// SOL_SOCKET / options
#define WIN_SOL_SOCKET    0xFFFF
#define WIN_SO_REUSEADDR  0x0004
#define WIN_SO_KEEPALIVE  0x0008
#define WIN_SO_BROADCAST  0x0020
#define WIN_SO_LINGER     0x0080
#define WIN_SO_SNDBUF     0x1001
#define WIN_SO_RCVBUF     0x1002
#define WIN_SO_SNDTIMEO   0x1005
#define WIN_SO_RCVTIMEO   0x1006
#define WIN_SO_ERROR      0x1007
#define WIN_IPPROTO_TCP   6
#define WIN_TCP_NODELAY   0x0001

// ── Socket handle table ─────────────────────────────────────────────
#define WG_MAX_SOCKETS 128

struct WGWinsock {
    bool initialised;
    int  last_error;
    // Map Windows SOCKET values to real fds. Windows SOCKETs in 32-bit
    // are unsigned ints; we use a small table indexed by (handle - base).
    int  fds[WG_MAX_SOCKETS]; // -1 = unused
};

#define SOCK_BASE 0x1000u

WGWinsock *wg_winsock_create(void) {
    WGWinsock *ws = calloc(1, sizeof(WGWinsock));
    if (!ws) return NULL;
    for (int i = 0; i < WG_MAX_SOCKETS; i++) ws->fds[i] = -1;
    return ws;
}

void wg_winsock_destroy(WGWinsock *ws) {
    if (!ws) return;
    for (int i = 0; i < WG_MAX_SOCKETS; i++) {
        if (ws->fds[i] >= 0) close(ws->fds[i]);
    }
    free(ws);
}

static uint32_t alloc_socket(WGWinsock *ws, int fd) {
    for (int i = 0; i < WG_MAX_SOCKETS; i++) {
        if (ws->fds[i] < 0) {
            ws->fds[i] = fd;
            return SOCK_BASE + i;
        }
    }
    close(fd);
    return WIN_INVALID_SOCKET;
}

static int lookup_fd(WGWinsock *ws, uint32_t s) {
    if (s < SOCK_BASE || s >= SOCK_BASE + WG_MAX_SOCKETS) return -1;
    return ws->fds[s - SOCK_BASE];
}

static void free_socket(WGWinsock *ws, uint32_t s) {
    if (s < SOCK_BASE || s >= SOCK_BASE + WG_MAX_SOCKETS) return;
    int idx = s - SOCK_BASE;
    if (ws->fds[idx] >= 0) { close(ws->fds[idx]); ws->fds[idx] = -1; }
}

static int errno_to_wsa(int e) {
    switch (e) {
        case EWOULDBLOCK:   return WSAEWOULDBLOCK;
        case EINPROGRESS:   return WSAEINPROGRESS;
        case EALREADY:      return WSAEALREADY;
        case ECONNREFUSED:  return WSAECONNREFUSED;
        case ECONNRESET:    return WSAECONNRESET;
        case ECONNABORTED:  return WSAECONNABORTED;
        case ETIMEDOUT:     return WSAETIMEDOUT;
        case ENETUNREACH:   return WSAENETUNREACH;
        case EHOSTUNREACH:  return WSAEHOSTUNREACH;
        case EINVAL:        return WSAEINVAL;
        case EMSGSIZE:      return WSAEMSGSIZE;
        case ENOTCONN:      return WSAENOTCONN;
        case EAFNOSUPPORT:  return WSAEAFNOSUPPORT;
        case EBADF:         return WSAENOTSOCK;
        default:            return WSAEINVAL;
    }
}

// ── Win32 sockaddr ↔ BSD sockaddr conversion ────────────────────────
// Windows sockaddr_in is identical to BSD (sa_family at +0 as uint16_t,
// port at +2, addr at +4). sockaddr_in6 is also layout-compatible.

static void read_sockaddr(void *blink, uint32_t guest_ptr, int len,
                          struct sockaddr_storage *out, socklen_t *outlen) {
    memset(out, 0, sizeof(*out));
    if (!guest_ptr || len <= 0) { *outlen = 0; return; }
    if (len > (int)sizeof(*out)) len = (int)sizeof(*out);
    wg_blink_read_mem(blink, guest_ptr, out, len);
    // Windows AF_INET6 = 23, BSD AF_INET6 = 30 (on macOS/iOS)
    if (((struct sockaddr *)out)->sa_family == WIN_AF_INET6)
        ((struct sockaddr *)out)->sa_family = AF_INET6;
    *outlen = (socklen_t)len;
}

static void write_sockaddr(void *blink, uint32_t guest_ptr, uint32_t guest_len_ptr,
                           const struct sockaddr_storage *sa, socklen_t salen) {
    if (!guest_ptr || !guest_len_ptr) return;
    // Fix AF back to Windows convention
    struct sockaddr_storage tmp;
    memcpy(&tmp, sa, salen > sizeof(tmp) ? sizeof(tmp) : salen);
    if (((struct sockaddr *)&tmp)->sa_family == AF_INET6)
        ((struct sockaddr *)&tmp)->sa_family = WIN_AF_INET6;
    uint32_t buflen = 0;
    wg_blink_read_mem(blink, guest_len_ptr, &buflen, 4);
    uint32_t copy = salen < buflen ? salen : buflen;
    wg_blink_write_mem(blink, guest_ptr, &tmp, copy);
    uint32_t written = salen;
    wg_blink_write_mem(blink, guest_len_ptr, &written, 4);
}

// ── Handler ─────────────────────────────────────────────────────────
bool wg_winsock_handle(WGWinsock *ws, const char *fn,
                       uint32_t *args, uint64_t *out_ret,
                       void *blink) {
    // ── WSAStartup(wVersionRequested, lpWSAData) ────────────────────
    if (strcmp(fn, "WSAStartup") == 0) {
        ws->initialised = true;
        ws->last_error = 0;
        // Fill WSAData at args[1]: wVersion, wHighVersion, then strings
        if (args[1]) {
            uint8_t data[400];
            memset(data, 0, sizeof(data));
            uint16_t ver = (uint16_t)args[0];
            memcpy(data + 0, &ver, 2);      // wVersion
            memcpy(data + 2, &ver, 2);      // wHighVersion
            const char *desc = "WineGlass WS2";
            memcpy(data + 4, desc, strlen(desc));
            wg_blink_write_mem(blink, args[1], data, 400);
        }
        WG_LOGI(TAG, "WSAStartup(0x%X) -> 0", args[0]);
        *out_ret = 0;
        return true;
    }

    if (strcmp(fn, "WSACleanup") == 0) {
        ws->initialised = false;
        *out_ret = 0;
        return true;
    }

    // ── WSAGetLastError / WSASetLastError ────────────────────────────
    if (strcmp(fn, "WSAGetLastError") == 0) {
        *out_ret = (uint32_t)ws->last_error;
        return true;
    }
    if (strcmp(fn, "WSASetLastError") == 0) {
        ws->last_error = (int)args[0];
        *out_ret = 0;
        return true;
    }

    // ── socket(af, type, protocol) ──────────────────────────────────
    if (strcmp(fn, "socket") == 0) {
        int af = (int)args[0];
        int type = (int)args[1];
        int proto = (int)args[2];
        if (af == WIN_AF_INET6) af = AF_INET6;
        int fd = socket(af, type, proto);
        if (fd < 0) {
            ws->last_error = errno_to_wsa(errno);
            WG_LOGW(TAG, "socket(%d,%d,%d) failed: %s", args[0], args[1], args[2], strerror(errno));
            *out_ret = WIN_INVALID_SOCKET;
        } else {
            uint32_t s = alloc_socket(ws, fd);
            WG_LOGI(TAG, "socket(%d,%d,%d) -> 0x%X (fd=%d)", args[0], args[1], args[2], s, fd);
            *out_ret = s;
        }
        return true;
    }

    // ── closesocket(s) ──────────────────────────────────────────────
    if (strcmp(fn, "closesocket") == 0) {
        free_socket(ws, args[0]);
        WG_LOGD(TAG, "closesocket(0x%X)", args[0]);
        *out_ret = 0;
        return true;
    }

    // ── connect(s, name, namelen) ───────────────────────────────────
    if (strcmp(fn, "connect") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        struct sockaddr_storage sa; socklen_t salen;
        read_sockaddr(blink, args[1], (int)args[2], &sa, &salen);
        char ipstr[64] = {0};
        if (sa.ss_family == AF_INET) {
            struct sockaddr_in *s4 = (struct sockaddr_in *)&sa;
            inet_ntop(AF_INET, &s4->sin_addr, ipstr, sizeof(ipstr));
            WG_LOGI(TAG, "connect(0x%X, %s:%d)", args[0], ipstr, ntohs(s4->sin_port));
        } else {
            WG_LOGI(TAG, "connect(0x%X, af=%d)", args[0], sa.ss_family);
        }
        int r = connect(fd, (struct sockaddr *)&sa, salen);
        if (r < 0) {
            ws->last_error = errno_to_wsa(errno);
            *out_ret = WIN_SOCKET_ERROR;
        } else {
            *out_ret = 0;
        }
        return true;
    }

    // ── send(s, buf, len, flags) ────────────────────────────────────
    if (strcmp(fn, "send") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        uint32_t len = args[2];
        if (len > 65536) len = 65536;
        uint8_t *buf = malloc(len);
        if (!buf) { ws->last_error = WSAEINVAL; *out_ret = WIN_SOCKET_ERROR; return true; }
        wg_blink_read_mem(blink, args[1], buf, len);
        ssize_t sent = send(fd, buf, len, 0);
        free(buf);
        if (sent < 0) {
            ws->last_error = errno_to_wsa(errno);
            *out_ret = WIN_SOCKET_ERROR;
        } else {
            WG_LOGD(TAG, "send(0x%X, %d) -> %zd", args[0], len, sent);
            *out_ret = (uint32_t)sent;
        }
        return true;
    }

    // ── recv(s, buf, len, flags) ────────────────────────────────────
    if (strcmp(fn, "recv") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        uint32_t len = args[2];
        if (len > 65536) len = 65536;
        uint8_t *buf = malloc(len);
        if (!buf) { ws->last_error = WSAEINVAL; *out_ret = WIN_SOCKET_ERROR; return true; }
        ssize_t got = recv(fd, buf, len, 0);
        if (got < 0) {
            free(buf);
            ws->last_error = errno_to_wsa(errno);
            *out_ret = WIN_SOCKET_ERROR;
        } else {
            if (got > 0) wg_blink_write_mem(blink, args[1], buf, (uint32_t)got);
            free(buf);
            WG_LOGD(TAG, "recv(0x%X, %d) -> %zd", args[0], len, got);
            *out_ret = (uint32_t)got;
        }
        return true;
    }

    // ── select(nfds, readfds, writefds, exceptfds, timeout) ─────────
    if (strcmp(fn, "select") == 0) {
        // Windows fd_set: { u_int fd_count; SOCKET fd_array[FD_SETSIZE]; }
        // We only support small sets. For now, return immediately with
        // all sockets ready (non-blocking check).
        // TODO: proper select with real fd_sets
        *out_ret = 1;
        return true;
    }

    // ── setsockopt(s, level, optname, optval, optlen) ───────────────
    if (strcmp(fn, "setsockopt") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        int level = (int)args[1];
        int opt = (int)args[2];
        // Map Windows constants to BSD
        if (level == WIN_SOL_SOCKET) level = SOL_SOCKET;
        if (level == WIN_IPPROTO_TCP) level = IPPROTO_TCP;
        // Map option names
        int bsd_opt = opt;
        if (level == SOL_SOCKET) {
            switch (opt) {
                case WIN_SO_REUSEADDR: bsd_opt = SO_REUSEADDR; break;
                case WIN_SO_KEEPALIVE: bsd_opt = SO_KEEPALIVE; break;
                case WIN_SO_BROADCAST: bsd_opt = SO_BROADCAST; break;
                case WIN_SO_LINGER:    bsd_opt = SO_LINGER; break;
                case WIN_SO_SNDBUF:    bsd_opt = SO_SNDBUF; break;
                case WIN_SO_RCVBUF:    bsd_opt = SO_RCVBUF; break;
                case WIN_SO_SNDTIMEO:  bsd_opt = SO_SNDTIMEO; break;
                case WIN_SO_RCVTIMEO:  bsd_opt = SO_RCVTIMEO; break;
                case WIN_SO_ERROR:     bsd_opt = SO_ERROR; break;
                default: break;
            }
        } else if (level == IPPROTO_TCP) {
            if (opt == WIN_TCP_NODELAY) bsd_opt = TCP_NODELAY;
        }
        uint32_t optlen = args[4];
        if (optlen > 64) optlen = 64;
        uint8_t optval[64] = {0};
        if (args[3] && optlen) wg_blink_read_mem(blink, args[3], optval, optlen);
        int r = setsockopt(fd, level, bsd_opt, optval, optlen);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else *out_ret = 0;
        return true;
    }

    // ── getsockopt(s, level, optname, optval, optlen) ───────────────
    if (strcmp(fn, "getsockopt") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        int level = (int)args[1] == WIN_SOL_SOCKET ? SOL_SOCKET : (int)args[1];
        int opt = (int)args[2];
        if (level == SOL_SOCKET && opt == WIN_SO_ERROR) opt = SO_ERROR;
        uint8_t optval[64] = {0};
        socklen_t optlen = 64;
        int r = getsockopt(fd, level, opt, optval, &optlen);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else {
            if (args[3]) wg_blink_write_mem(blink, args[3], optval, optlen);
            if (args[4]) wg_blink_write_mem(blink, args[4], &optlen, 4);
            *out_ret = 0;
        }
        return true;
    }

    // ── ioctlsocket(s, cmd, argp) ───────────────────────────────────
    if (strcmp(fn, "ioctlsocket") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        uint32_t cmd = args[1];
        if (cmd == WIN_FIONBIO) {
            uint32_t val = 0;
            if (args[2]) wg_blink_read_mem(blink, args[2], &val, 4);
            int flags = fcntl(fd, F_GETFL, 0);
            if (val) flags |= O_NONBLOCK; else flags &= ~O_NONBLOCK;
            fcntl(fd, F_SETFL, flags);
            WG_LOGD(TAG, "ioctlsocket(0x%X, FIONBIO, %u)", args[0], val);
            *out_ret = 0;
        } else if (cmd == WIN_FIONREAD) {
            int avail = 0;
            ioctl(fd, FIONREAD, &avail);
            if (args[2]) { uint32_t v = (uint32_t)avail; wg_blink_write_mem(blink, args[2], &v, 4); }
            *out_ret = 0;
        } else {
            WG_LOGW(TAG, "ioctlsocket: unknown cmd 0x%X", cmd);
            *out_ret = 0;
        }
        return true;
    }

    // ── shutdown(s, how) ────────────────────────────────────────────
    if (strcmp(fn, "shutdown") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        shutdown(fd, (int)args[1]);
        *out_ret = 0;
        return true;
    }

    // ── bind(s, name, namelen) ──────────────────────────────────────
    if (strcmp(fn, "bind") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        struct sockaddr_storage sa; socklen_t salen;
        read_sockaddr(blink, args[1], (int)args[2], &sa, &salen);
        int r = bind(fd, (struct sockaddr *)&sa, salen);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else *out_ret = 0;
        return true;
    }

    // ── listen(s, backlog) ──────────────────────────────────────────
    if (strcmp(fn, "listen") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        int r = listen(fd, (int)args[1]);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else *out_ret = 0;
        return true;
    }

    // ── getpeername(s, name, namelen) ────────────────────────────────
    if (strcmp(fn, "getpeername") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        struct sockaddr_storage sa; socklen_t salen = sizeof(sa);
        int r = getpeername(fd, (struct sockaddr *)&sa, &salen);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else { write_sockaddr(blink, args[1], args[2], &sa, salen); *out_ret = 0; }
        return true;
    }

    // ── getsockname(s, name, namelen) ───────────────────────────────
    if (strcmp(fn, "getsockname") == 0) {
        int fd = lookup_fd(ws, args[0]);
        if (fd < 0) { ws->last_error = WSAENOTSOCK; *out_ret = WIN_SOCKET_ERROR; return true; }
        struct sockaddr_storage sa; socklen_t salen = sizeof(sa);
        int r = getsockname(fd, (struct sockaddr *)&sa, &salen);
        if (r < 0) { ws->last_error = errno_to_wsa(errno); *out_ret = WIN_SOCKET_ERROR; }
        else { write_sockaddr(blink, args[1], args[2], &sa, salen); *out_ret = 0; }
        return true;
    }

    // ── htons / htonl / ntohs / ntohl ───────────────────────────────
    if (strcmp(fn, "htons") == 0) { *out_ret = htons((uint16_t)args[0]); return true; }
    if (strcmp(fn, "htonl") == 0) { *out_ret = htonl(args[0]); return true; }
    if (strcmp(fn, "ntohs") == 0) { *out_ret = ntohs((uint16_t)args[0]); return true; }
    if (strcmp(fn, "ntohl") == 0) { *out_ret = ntohl(args[0]); return true; }

    // ── inet_addr(cp) ───────────────────────────────────────────────
    if (strcmp(fn, "inet_addr") == 0) {
        char str[64] = {0};
        if (args[0]) wg_blink_read_mem(blink, args[0], str, 63);
        struct in_addr ia;
        if (inet_aton(str, &ia)) *out_ret = ia.s_addr;
        else *out_ret = 0xFFFFFFFF; // INADDR_NONE
        return true;
    }

    // ── inet_ntoa(in_addr) ──────────────────────────────────────────
    if (strcmp(fn, "inet_ntoa") == 0) {
        // args[0] is the in_addr value passed by value (4 bytes)
        struct in_addr ia; ia.s_addr = args[0];
        const char *s = inet_ntoa(ia);
        // Write to a fixed guest address (static buffer, like real inet_ntoa)
        uint32_t buf_addr = 0xA00200;
        wg_blink_write_mem(blink, buf_addr, s, (uint32_t)strlen(s) + 1);
        *out_ret = buf_addr;
        return true;
    }

    // ── getaddrinfo(nodename, servname, hints, res) ─────────────────
    if (strcmp(fn, "getaddrinfo") == 0) {
        char node[256] = {0}, serv[64] = {0};
        if (args[0]) wg_blink_read_mem(blink, args[0], node, 255);
        if (args[1]) wg_blink_read_mem(blink, args[1], serv, 63);

        // Read hints if provided
        struct addrinfo hints_h, *hints_p = NULL;
        memset(&hints_h, 0, sizeof(hints_h));
        if (args[2]) {
            uint32_t h[8] = {0};
            wg_blink_read_mem(blink, args[2], h, 32);
            // Win32 addrinfo: flags, family, socktype, protocol, addrlen, canonname, addr, next
            hints_h.ai_flags = (int)h[0];
            hints_h.ai_family = (int)h[1];
            if (hints_h.ai_family == WIN_AF_INET6) hints_h.ai_family = AF_INET6;
            hints_h.ai_socktype = (int)h[2];
            hints_h.ai_protocol = (int)h[3];
            hints_p = &hints_h;
        }

        WG_LOGI(TAG, "getaddrinfo('%s', '%s')", node, serv);

        struct addrinfo *res = NULL;
        int err = getaddrinfo(node[0] ? node : NULL, serv[0] ? serv : NULL, hints_p, &res);
        if (err != 0) {
            WG_LOGW(TAG, "getaddrinfo failed: %s", gai_strerror(err));
            // Map EAI errors to Winsock errors
            ws->last_error = WSAEHOSTUNREACH;
            *out_ret = 11001; // WSAHOST_NOT_FOUND
            return true;
        }

        // Serialize addrinfo chain into guest memory. Layout per node:
        // Win32 addrinfo (32 bytes) + sockaddr data
        // We'll use a bump allocator in a reserved guest region.
        static uint32_t s_gai_ptr = 0xB00000;
        uint32_t ptr = s_gai_ptr;
        uint32_t prev_next = 0;

        for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
            uint32_t node_base = ptr;
            uint32_t sa_ptr = node_base + 32; // sockaddr right after addrinfo
            uint32_t sa_len = ai->ai_addrlen;
            uint32_t next_ptr = ai->ai_next ? (sa_ptr + ((sa_len + 3) & ~3u)) : 0;

            // Write addrinfo struct (Win32 layout)
            uint32_t aih[8] = {0};
            aih[0] = (uint32_t)ai->ai_flags;
            aih[1] = (uint32_t)ai->ai_family;
            if (aih[1] == AF_INET6) aih[1] = WIN_AF_INET6;
            aih[2] = (uint32_t)ai->ai_socktype;
            aih[3] = (uint32_t)ai->ai_protocol;
            aih[4] = sa_len;
            aih[5] = 0; // canonname (NULL)
            aih[6] = sa_ptr;
            aih[7] = next_ptr;
            wg_blink_write_mem(blink, node_base, aih, 32);

            // Write sockaddr
            if (ai->ai_addr && sa_len > 0) {
                struct sockaddr_storage tmp;
                memcpy(&tmp, ai->ai_addr, sa_len);
                if (((struct sockaddr *)&tmp)->sa_family == AF_INET6)
                    ((struct sockaddr *)&tmp)->sa_family = WIN_AF_INET6;
                wg_blink_write_mem(blink, sa_ptr, &tmp, sa_len);
            }

            if (prev_next) {
                // Patch previous node's next pointer
                wg_blink_write_mem(blink, prev_next, &node_base, 4);
            }
            prev_next = node_base + 28; // offset of ai_next
            ptr = next_ptr ? next_ptr : (sa_ptr + ((sa_len + 3) & ~3u));
        }

        // Write pointer to first node
        if (args[3]) {
            uint32_t first = s_gai_ptr;
            wg_blink_write_mem(blink, args[3], &first, 4);
        }

        s_gai_ptr = ptr;
        freeaddrinfo(res);
        WG_LOGI(TAG, "getaddrinfo -> OK");
        *out_ret = 0;
        return true;
    }

    // ── freeaddrinfo(ai) ────────────────────────────────────────────
    if (strcmp(fn, "freeaddrinfo") == 0) {
        // Guest memory is bump-allocated; nothing to free
        *out_ret = 0;
        return true;
    }

    // ── WSASend / WSARecv / WSASendTo / WSARecvFrom ─────────────────
    // These use WSABUF structures. For now, stub them.
    if (strcmp(fn, "WSASend") == 0 || strcmp(fn, "WSASendTo") == 0) {
        ws->last_error = WSAENOTCONN;
        *out_ret = WIN_SOCKET_ERROR;
        return true;
    }
    if (strcmp(fn, "WSARecv") == 0 || strcmp(fn, "WSARecvFrom") == 0) {
        ws->last_error = WSAENOTCONN;
        *out_ret = WIN_SOCKET_ERROR;
        return true;
    }

    // ── WSAIoctl ────────────────────────────────────────────────────
    if (strcmp(fn, "WSAIoctl") == 0) {
        *out_ret = WIN_SOCKET_ERROR;
        ws->last_error = WSAEINVAL;
        return true;
    }

    // ── WSASocketW(af, type, proto, info, group, flags) ─────────────
    if (strcmp(fn, "WSASocketW") == 0) {
        int af = (int)args[0], type = (int)args[1], proto = (int)args[2];
        if (af == WIN_AF_INET6) af = AF_INET6;
        int fd = socket(af, type, proto);
        if (fd < 0) {
            ws->last_error = errno_to_wsa(errno);
            *out_ret = WIN_INVALID_SOCKET;
        } else {
            *out_ret = alloc_socket(ws, fd);
            WG_LOGI(TAG, "WSASocketW(%d,%d,%d) -> 0x%X", args[0], args[1], args[2], (uint32_t)*out_ret);
        }
        return true;
    }

    // ── WSAEnumNetworkEvents(s, hEvent, lpNetworkEvents) ────────────
    if (strcmp(fn, "WSAEnumNetworkEvents") == 0) {
        if (args[2]) {
            uint8_t zero[36] = {0}; // WSANETWORKEVENTS
            wg_blink_write_mem(blink, args[2], zero, 36);
        }
        *out_ret = 0;
        return true;
    }

    // ── WSAEventSelect(s, hEvent, lNetworkEvents) ───────────────────
    if (strcmp(fn, "WSAEventSelect") == 0) {
        // Make socket non-blocking (like WSAEventSelect does)
        int fd = lookup_fd(ws, args[0]);
        if (fd >= 0) {
            int flags = fcntl(fd, F_GETFL, 0);
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
        }
        *out_ret = 0;
        return true;
    }

    return false; // not handled
}
