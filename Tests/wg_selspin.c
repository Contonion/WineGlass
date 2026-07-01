// wg_selspin.c — MINIMAL single-threaded select-readloop repro.
// No worker thread, no events. Just: connect (blocking) + send + a non-blocking
// select(readfds) loop. Purpose: does a stack-local fd_set keep fd_count across
// repeated select() calls when there is only ONE thread? If fd_count stays 1
// here (but went to 0 in the multi-threaded reactor probe), the bug is thread
// stack corruption. CRT printf is auto-stubbed, so format by hand.
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <string.h>

static void put(char *b, int *o, const char *s){ while(*s) b[(*o)++]=*s++; }
static void putu(char *b, int *o, unsigned v){ char t[12]; int n=0; if(!v)t[n++]='0'; while(v){t[n++]='0'+v%10;v/=10;} while(n)b[(*o)++]=t[--n]; }
static void dbg2(const char*s, unsigned v){ char b[128]; int o=0; put(b,&o,s); putu(b,&o,v); b[o++]='\n'; b[o]=0; OutputDebugStringA(b); }
static void dbg(const char*s){ char b[128]; int o=0; put(b,&o,s); b[o++]='\n'; b[o]=0; OutputDebugStringA(b); }

static HANDLE g_job, g_done;
static DWORD WINAPI worker(LPVOID p){ (void)p;
#ifdef PINGPONG
#ifdef WORKEREXIT
    for(int i=0;i<6;i++){ WaitForSingleObject(g_job, INFINITE); SetEvent(g_done); }
    OutputDebugStringA("SELSPIN/worker: exiting\n");   // worker RETURNS (thread-return path)
#else
    for(;;){ WaitForSingleObject(g_job, INFINITE); SetEvent(g_done); }
#endif
#else
    for(;;) Sleep(1000);
#endif
    return 0; }

int main(void){
    WSADATA w; WSAStartup(MAKEWORD(2,2), &w);
    dbg("SELSPIN: start");
#ifdef WITH_WORKER
    g_job = CreateEventA(NULL,FALSE,FALSE,NULL); g_done = CreateEventA(NULL,FALSE,FALSE,NULL);
    CreateThread(NULL,0,worker,NULL,0,NULL);
    dbg("SELSPIN: worker created");
#ifdef PINGPONG
    for (int k=0;k<3;k++){ SetEvent(g_job); WaitForSingleObject(g_done, 1000); }  // force context switches
    dbg("SELSPIN: pingpong done");
#endif
#endif
    struct addrinfo hints, *res=0; memset(&hints,0,sizeof hints);
    hints.ai_family=AF_INET; hints.ai_socktype=SOCK_STREAM;
    if (getaddrinfo("example.com","80",&hints,&res)||!res){ dbg("SELSPIN: dns FAIL"); return 1; }
    SOCKET s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (connect(s, res->ai_addr, (int)res->ai_addrlen)!=0){ dbg2("SELSPIN: connect FAIL err=", WSAGetLastError()); return 1; }
    dbg("SELSPIN: connected");
#ifdef CONNSELECT
    // Interleave a select(writable) loop with worker pings, like the reactor probe.
    for (int i=0;i<5;i++){
        fd_set wr; FD_ZERO(&wr); FD_SET(s,&wr);
        struct timeval tv={0,100000};
        select(0,NULL,&wr,NULL,&tv);
        SetEvent(g_job); WaitForSingleObject(g_done, 200);
    }
    dbg("SELSPIN: connselect done");
#endif
    const char *req = "GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n";
    dbg2("SELSPIN: send=", (unsigned)send(s, req, (int)strlen(req), 0));
    u_long nb=1; ioctlsocket(s, FIONBIO, &nb);

    int total=0, fires=0;
    for (int i=0;i<60000 && total==0;i++){
        fd_set rd; FD_ZERO(&rd); FD_SET(s,&rd);
        struct timeval tv={0,100000};
        int n = select(0,&rd,NULL,NULL,&tv);
        if (n>0 && FD_ISSET(s,&rd)){
            fires++;
            char buf[2048]; int got=recv(s,buf,sizeof buf,0);
            if (got>0){ total+=got; dbg2("SELSPIN: recv bytes=", (unsigned)got); }
            else if (got==0){ dbg("SELSPIN: peer closed"); break; }
        }
        if ((i%10000)==0) dbg2("SELSPIN: loop i=", (unsigned)i);
    }
    dbg2("SELSPIN: DONE total=", (unsigned)total);
    dbg2("SELSPIN: sel_fires=", (unsigned)fires);
    closesocket(s); freeaddrinfo(res); WSACleanup();
    return 0;
}
