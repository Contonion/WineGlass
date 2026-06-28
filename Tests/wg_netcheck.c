// wg_netcheck.c — Minimal Win32 WinSock HTTP GET to validate the WineGlass
// network stack end-to-end (getaddrinfo -> socket -> connect -> send -> recv)
// with BLOCKING sockets — no IOCP, no select, no TLS, no async state machine.
// This isolates the core socket path that "any app" relies on, away from
// Steam's bespoke CTCPConnection/IOCP engine.
//
// Cross-compile (32-bit, matches WineGlass primary target):
//   i686-w64-mingw32-gcc -O2 -s -static -o Tests/wg_netcheck.exe \
//       Tests/wg_netcheck.c -lws2_32
//
// Output goes through OutputDebugStringA so it appears in the WineGlass log as
// "DbgPrint: ...". Deploy the .exe to the device Documents (or load via picker).

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

static void dbg(const char *fmt, ...) {
    char buf[1024];
    va_list ap; va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    OutputDebugStringA(buf);
}

int main(void) {
    dbg("NETCHECK: start");

    WSADATA wsa;
    int r = WSAStartup(MAKEWORD(2, 2), &wsa);
    dbg("NETCHECK: WSAStartup -> %d", r);
    if (r != 0) return 1;

    const char *host = "example.com";
    const char *port = "80";

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    int err = getaddrinfo(host, port, &hints, &res);
    dbg("NETCHECK: getaddrinfo('%s') -> %d", host, err);
    if (err != 0 || !res) return 1;

    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    char ipstr[64] = {0};
    inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
    dbg("NETCHECK: resolved -> %s (family=%d addrlen=%d)",
        ipstr, (int)res->ai_family, (int)res->ai_addrlen);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    dbg("NETCHECK: socket -> %u", (unsigned)s);
    if (s == INVALID_SOCKET) return 1;

    // Blocking connect — should return 0 only when fully connected.
    r = connect(s, res->ai_addr, (int)res->ai_addrlen);
    dbg("NETCHECK: connect -> %d (err=%d)", r, WSAGetLastError());
    freeaddrinfo(res);
    if (r != 0) { closesocket(s); return 1; }

    const char *req =
        "GET / HTTP/1.0\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    int sent = send(s, req, (int)strlen(req), 0);
    dbg("NETCHECK: send -> %d (err=%d)", sent, WSAGetLastError());

    char buf[4096];
    int total = 0, n;
    while ((n = recv(s, buf + total, (int)sizeof(buf) - 1 - total, 0)) > 0) {
        total += n;
        if (total >= (int)sizeof(buf) - 1) break;
    }
    dbg("NETCHECK: recv total=%d (last n=%d err=%d)", total, n, WSAGetLastError());

    if (total > 0) {
        buf[total] = 0;
        char *eol = strchr(buf, '\n');
        if (eol) *eol = 0;
        dbg("NETCHECK: HTTP status: %s", buf);
        dbg("NETCHECK: *** PASS — real HTTP response received ***");
    } else {
        dbg("NETCHECK: *** FAIL — no data received ***");
    }

    closesocket(s);
    WSACleanup();
    dbg("NETCHECK: done");
    return 0;
}
