// wg_reactorprobe.c — reproduces the SHAPE of Steam's bootstrapper download
// reactor with a log line at every step, to pin down the interpreter(Mac) vs
// JIT(device) timing divergence that makes Steam hang on the device. It exercises
// the exact primitives Steam's flow depends on:
//   - CreateThread (a worker), bidirectional auto-reset events (job<->done)
//   - a MAIN-thread non-blocking connect + select(write) + send + select(read)+recv
//     loop (this is where Steam's tid=1 hangs), while pinging the worker each turn
// No TLS: isolates the threading/socket SCHEDULING from the crypto. Target is
// cdn.steamstatic.com:80 so recv returns a real HTTP response (validates the full
// path end to end). Every step is logged via OutputDebugStringA -> appears in the
// WineGlass log as "DbgPrint: RP/...". Deterministic: bounded loops + finite waits,
// so it always reaches "RP: VERDICT ..." instead of hanging.
//
// Build (32-bit, matches WineGlass target):
//   i686-w64-mingw32-gcc -O2 -s -static -o Tests/wg_reactorprobe.exe \
//       Tests/wg_reactorprobe.c -lws2_32

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>

// Hand-rolled formatter: the CRT printf/vsnprintf family is auto-stubbed in the
// engine (produces empty strings), so we cannot use it. Supports %d %u %ld %lu %p
// %s and %.<n>s — the only specifiers this probe uses.
static char *put_str(char *p, char *end, const char *s, int maxlen) {
    if (!s) s = "(null)";
    for (int i = 0; (maxlen < 0 || i < maxlen) && *s && p < end - 1; i++) *p++ = *s++;
    return p;
}
static char *put_uint(char *p, char *end, unsigned long v) {
    char tmp[24]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v && n < 24) { tmp[n++] = (char)('0' + (v % 10)); v /= 10; }
    while (n-- && p < end - 1) *p++ = tmp[n];
    return p;
}
static char *put_int(char *p, char *end, long v) {
    if (v < 0 && p < end - 1) { *p++ = '-'; return put_uint(p, end, (unsigned long)(-v)); }
    return put_uint(p, end, (unsigned long)v);
}
static char *put_hex(char *p, char *end, unsigned long v) {
    const char *hx = "0123456789ABCDEF"; char tmp[16]; int n = 0;
    if (v == 0) tmp[n++] = '0';
    while (v && n < 16) { tmp[n++] = hx[v & 0xF]; v >>= 4; }
    if (p < end - 1) *p++ = '0'; if (p < end - 1) *p++ = 'x';
    while (n-- && p < end - 1) *p++ = tmp[n];
    return p;
}
static void dbg(const char *fmt, ...) {
    char buf[1024]; char *p = buf, *end = buf + sizeof(buf);
    va_list ap; va_start(ap, fmt);
    for (const char *f = fmt; *f && p < end - 1; f++) {
        if (*f != '%') { *p++ = *f; continue; }
        f++;
        int lng = 0, prec = -1;
        if (*f == '.') { f++; prec = 0; while (*f >= '0' && *f <= '9') { prec = prec*10 + (*f-'0'); f++; } }
        while (*f == 'l') { lng = 1; f++; }
        switch (*f) {
            case 'd': p = put_int(p, end, lng ? va_arg(ap, long) : (long)va_arg(ap, int)); break;
            case 'u': p = put_uint(p, end, lng ? va_arg(ap, unsigned long) : (unsigned long)va_arg(ap, unsigned int)); break;
            case 'p': p = put_hex(p, end, (unsigned long)(size_t)va_arg(ap, void*)); break;
            case 's': p = put_str(p, end, va_arg(ap, const char*), prec); break;
            case '%': if (p < end-1) *p++ = '%'; break;
            default:  if (p < end-1) *p++ = '%'; if (p < end-1) *p++ = *f; break;
        }
    }
    va_end(ap);
    *p = 0;
    OutputDebugStringA(buf);
}

static HANDLE g_job;        // main -> worker: "do a unit of work"
static HANDLE g_done;       // worker -> main: "unit complete"
static volatile LONG g_units;   // incremented by the worker each unit
static volatile LONG g_stop;    // main tells worker to exit

// The worker models Steam's TLS worker: it sleeps on an auto-reset event, does a
// tiny bit of work when signalled, and signals back. We're verifying our engine
// delivers these cross-thread wakes promptly and in order.
static DWORD WINAPI worker(LPVOID p) {
    (void)p;
    dbg("RP/worker: start tid=%lu", (unsigned long)GetCurrentThreadId());
    for (int i = 0; i < 64; i++) {
        if (g_stop) break;
        DWORD w = WaitForSingleObject(g_job, 3000);   // wait for a job
        if (w == WAIT_TIMEOUT) { dbg("RP/worker: job WAIT_TIMEOUT (i=%d)", i); continue; }
        InterlockedIncrement(&g_units);
        dbg("RP/worker: woke i=%d (wait=%lu) units=%ld -> SetEvent(done)", i, (unsigned long)w, g_units);
        SetEvent(g_done);
    }
    dbg("RP/worker: exit (units=%ld)", g_units);
    return 0;
}

int main(void) {
    dbg("RP: start tid=%lu", (unsigned long)GetCurrentThreadId());

    WSADATA wsa;
    int r = WSAStartup(MAKEWORD(2, 2), &wsa);
    dbg("RP: WSAStartup -> %d", r);
    if (r != 0) { dbg("RP: VERDICT FAIL (wsastartup)"); return 1; }

    g_job  = CreateEventA(NULL, FALSE, FALSE, NULL);   // auto-reset, nonsignaled
    g_done = CreateEventA(NULL, FALSE, FALSE, NULL);
    dbg("RP: events job=%p done=%p", g_job, g_done);

    HANDLE th = CreateThread(NULL, 0, worker, NULL, 0, NULL);
    dbg("RP: CreateThread worker -> %p", th);
    if (!th) { dbg("RP: VERDICT FAIL (createthread)"); return 1; }

    // --- ping/pong the worker a few times BEFORE any socket work, to test pure
    //     cross-thread event delivery + scheduling in isolation ---
    for (int i = 0; i < 3; i++) {
        dbg("RP/main: ping %d -> SetEvent(job)", i);
        SetEvent(g_job);
        DWORD w = WaitForSingleObject(g_done, 3000);
        dbg("RP/main: pong %d (wait=%lu units=%ld)", i, (unsigned long)w, g_units);
        if (w == WAIT_TIMEOUT) { dbg("RP: VERDICT FAIL (event pingpong stalled at %d)", i); g_stop=1; SetEvent(g_job); return 1; }
    }
    dbg("RP/main: event ping/pong OK (3/3)");

    // --- resolve + non-blocking connect + select(write) + send + select(read)+recv
    //     to cdn.steamstatic.com:80 — the same socket pattern as Steam's tid=1 ---
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET; hints.ai_socktype = SOCK_STREAM; hints.ai_protocol = IPPROTO_TCP;
    int err = getaddrinfo("example.com", "80", &hints, &res);
    dbg("RP: getaddrinfo -> %d", err);
    if (err != 0 || !res) { dbg("RP: VERDICT FAIL (dns)"); return 1; }
    char ip[64] = {0};
    inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, ip, sizeof(ip));
    dbg("RP: resolved -> %s", ip);

    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    dbg("RP: socket -> %u", (unsigned)s);
    u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);   // non-blocking, like Steam's tid=1

    int cr = connect(s, res->ai_addr, (int)res->ai_addrlen);
    int ce = WSAGetLastError();
    dbg("RP: connect -> %d (err=%d, WSAEWOULDBLOCK=%d expected)", cr, ce, WSAEWOULDBLOCK);

    // select for WRITABLE = connect complete (Steam's tid=1 does exactly this)
    int connected = 0;
    for (int i = 0; i < 50 && !connected; i++) {
        fd_set wr, ex; FD_ZERO(&wr); FD_ZERO(&ex); FD_SET(s, &wr); FD_SET(s, &ex);
        struct timeval tv = { 0, 100000 }; // 100ms
        int n = select(0, NULL, &wr, &ex, &tv);
        if (i < 5 || (i % 10) == 0)
            dbg("RP: connect-select i=%d -> %d (writable=%d except=%d)",
                i, n, FD_ISSET(s, &wr), FD_ISSET(s, &ex));
        if (n > 0 && FD_ISSET(s, &wr)) connected = 1;
        if (n > 0 && FD_ISSET(s, &ex)) { dbg("RP: VERDICT FAIL (connect except)"); return 1; }
        // ping the worker each iteration too (mimics Steam pumping a worker while polling)
        SetEvent(g_job); WaitForSingleObject(g_done, 200);
    }
    dbg("RP: connected=%d", connected);
    if (!connected) { dbg("RP: VERDICT FAIL (connect-select never writable)"); return 1; }

    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    int sent = send(s, req, (int)strlen(req), 0);
    dbg("RP: send -> %d", sent);
    if (sent <= 0) { dbg("RP: VERDICT FAIL (send err=%d)", WSAGetLastError()); return 1; }

    // TEST C — non-blocking select(readfds)+recv (Steam's tid=1 read loop). Our
    // select returns instantly (ignores its timeout), so this busy-spins; bounded
    // iteration count so it always finishes. Counts how often select reported
    // readable -> tells us if select(readfds) detects incoming data.
    int total = 0, sel_ready = 0;
    for (int i = 0; i < 60000 && total == 0; i++) {   // span real time; stop once we get data
        fd_set rd; FD_ZERO(&rd); FD_SET(s, &rd);
        struct timeval tv = { 0, 100000 };
        int n = select(0, &rd, NULL, NULL, &tv);
        if (n > 0 && FD_ISSET(s, &rd)) {
            sel_ready++;
            char buf[2048];
            int got = recv(s, buf, sizeof(buf), 0);
            if (got > 0) { total += got;
                dbg("RP: C recv i=%d -> %d bytes first='%.16s'", i, got, buf);
            } else if (got == 0) { dbg("RP: C peer closed (total=%d)", total); break; }
        }
        if ((i % 10000) == 0) dbg("RP: C read-loop i=%d (sel_fires=%d)", i, sel_ready);
    }
    int test_c = (total > 0);
    dbg("RP: TEST_C select-recv: %s (bytes=%d, select_ready_fired=%d)",
        test_c ? "PASS" : "FAIL", total, sel_ready);

    g_stop = 1; SetEvent(g_job);
    closesocket(s); freeaddrinfo(res);

    // Per-primitive summary — one line for an easy Mac-vs-device diff. Reaching here
    // at all means events+connect+send worked (they'd have early-returned FAIL
    // otherwise). selectrecv tells us if non-blocking select(readfds)+recv detects
    // the HTTP response.
    dbg("RP: SUMMARY events=PASS connect=PASS send=PASS selectrecv=%s (bytes=%d sel_fires=%d)",
        test_c ? "PASS" : "FAIL", total, sel_ready);
    dbg("RP: VERDICT DONE (threads+events+connect+send OK; selectrecv=%s)",
        test_c ? "PASS" : "FAIL");
    return 0;
}
