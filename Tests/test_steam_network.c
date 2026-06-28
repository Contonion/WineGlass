// test_steam_network.c — Direct native connectivity test for cdn.steamstatic.com:443
// Build: clang -o /tmp/test_net Tests/test_steam_network.c -framework Security
// Run:   /tmp/test_net
//
// Tests the raw BSD socket + SecureTransport stack that wg_schannel.c uses,
// bypassing the x86 engine entirely. If this fails, the problem is in the
// native network layer; if it succeeds, the bug is in the engine/thunk layer.

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wdeprecated-declarations"
#include <Security/SecureTransport.h>
#pragma clang diagnostic pop

static OSStatus ssl_read(SSLConnectionRef conn, void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    ssize_t n = read(fd, data, *len);
    if (n > 0)  { *len = (size_t)n; return noErr; }
    if (n == 0) { *len = 0; return errSSLClosedGraceful; }
    *len = 0;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? errSSLWouldBlock : errSSLInternal;
}

static OSStatus ssl_write(SSLConnectionRef conn, const void *data, size_t *len) {
    int fd = (int)(intptr_t)conn;
    ssize_t n = write(fd, data, *len);
    if (n >= 0) { *len = (size_t)n; return noErr; }
    *len = 0;
    return (errno == EAGAIN || errno == EWOULDBLOCK) ? errSSLWouldBlock : errSSLInternal;
}

static int set_blocking(int fd, int blocking) {
    int flags = fcntl(fd, F_GETFL, 0);
    if (blocking) flags &= ~O_NONBLOCK;
    else          flags |=  O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags);
}

int main(void) {
    const char *host = "cdn.steamstatic.com";
    const char *port = "443";
    const char *path = "/client/steam_client_win32";

    printf("=== Steam Network Test ===\n");
    printf("Target: %s:%s%s\n\n", host, port, path);

    // 1. Resolve
    printf("[1] getaddrinfo %s:%s ... ", host, port);
    fflush(stdout);
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    int err = getaddrinfo(host, port, &hints, &res);
    if (err || !res) {
        printf("FAIL: %s\n", gai_strerror(err));
        return 1;
    }
    char ipstr[64] = {0};
    struct sockaddr_in *sin = (struct sockaddr_in *)res->ai_addr;
    inet_ntop(AF_INET, &sin->sin_addr, ipstr, sizeof(ipstr));
    printf("OK -> %s\n", ipstr);

    // 2. Create socket
    printf("[2] socket() ... ");
    fflush(stdout);
    int fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (fd < 0) { printf("FAIL: %s\n", strerror(errno)); freeaddrinfo(res); return 1; }
    printf("OK (fd=%d)\n", fd);

    // 3. Non-blocking connect with 15s timeout (same as ConnectEx impl)
    printf("[3] connect %s:443 (15s timeout) ... ", ipstr);
    fflush(stdout);
    set_blocking(fd, 0);
    int cret = connect(fd, res->ai_addr, res->ai_addrlen);
    freeaddrinfo(res);
    if (cret < 0 && errno != EINPROGRESS) {
        printf("FAIL: %s\n", strerror(errno));
        close(fd); return 1;
    }
    fd_set wfds; FD_ZERO(&wfds); FD_SET(fd, &wfds);
    struct timeval tv = {15, 0};
    int sel = select(fd + 1, NULL, &wfds, NULL, &tv);
    if (sel <= 0) {
        printf("FAIL: %s\n", sel == 0 ? "timed out" : strerror(errno));
        close(fd); return 1;
    }
    int sock_err = 0; socklen_t sl = sizeof(sock_err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &sl);
    if (sock_err) { printf("FAIL: %s\n", strerror(sock_err)); close(fd); return 1; }
    set_blocking(fd, 1);
    printf("OK\n");

    // 4. TLS handshake
    printf("[4] TLS handshake (SecureTransport) ... ");
    fflush(stdout);
    SSLContextRef ssl = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
    SSLSetIOFuncs(ssl, ssl_read, ssl_write);
    SSLSetConnection(ssl, (SSLConnectionRef)(intptr_t)fd);
    SSLSetPeerDomainName(ssl, host, strlen(host));
    OSStatus sts;
    do { sts = SSLHandshake(ssl); } while (sts == errSSLWouldBlock);
    if (sts != noErr) {
        printf("FAIL: OSStatus=%d\n", (int)sts);
        SSLClose(ssl); CFRelease(ssl); close(fd); return 1;
    }
    SSLProtocol proto = 0; SSLGetNegotiatedProtocolVersion(ssl, &proto);
    printf("OK (proto=%d)\n", (int)proto);

    // 5. HTTP GET (HEAD to avoid huge download)
    printf("[5] Send HTTP HEAD request ... ");
    fflush(stdout);
    char req[512];
    snprintf(req, sizeof(req),
        "HEAD %s HTTP/1.0\r\nHost: %s\r\nUser-Agent: Valve/Steam\r\n\r\n",
        path, host);
    size_t sent = 0;
    do { sts = SSLWrite(ssl, req + sent, strlen(req) - sent, &sent); } while (sts == errSSLWouldBlock);
    if (sts != noErr) {
        printf("FAIL: SSLWrite OSStatus=%d\n", (int)sts);
        SSLClose(ssl); CFRelease(ssl); close(fd); return 1;
    }
    printf("OK (%zu bytes sent)\n", sent);

    // 6. Read response
    printf("[6] Read HTTP response ... ");
    fflush(stdout);
    char buf[4096]; size_t rcvd = 0;
    do { sts = SSLRead(ssl, buf, sizeof(buf)-1, &rcvd); } while (sts == errSSLWouldBlock && rcvd == 0);
    if (rcvd == 0) {
        printf("FAIL: no data (OSStatus=%d)\n", (int)sts);
        SSLClose(ssl); CFRelease(ssl); close(fd); return 1;
    }
    buf[rcvd] = 0;
    // Print first line of response
    char *eol = strchr(buf, '\n');
    if (eol) *eol = 0;
    printf("OK\n\nHTTP response: %s\n", buf);

    SSLClose(ssl); CFRelease(ssl); close(fd);
    printf("\n=== PASS: Network stack works ===\n");
    return 0;
}
