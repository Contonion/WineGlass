// wg_cvcheck.c — validate condition-variable block/wake (Steam's thread-pool
// coordination primitive). A worker parks on a CV waiting for work; main queues
// work items and Wakes the CV. If the worker processes all items, CV block/wake
// works. CRT printf is auto-stubbed, so format by hand.
#include <winsock2.h>
#include <windows.h>

static void put(char*b,int*o,const char*s){while(*s)b[(*o)++]=*s++;}
static void putu(char*b,int*o,unsigned v){char t[12];int n=0;if(!v)t[n++]='0';while(v){t[n++]='0'+v%10;v/=10;}while(n)b[(*o)++]=t[--n];}
static void dbg(const char*s){char b[128];int o=0;put(b,&o,s);b[o++]='\n';b[o]=0;OutputDebugStringA(b);}
static void dbg2(const char*s,unsigned v){char b[128];int o=0;put(b,&o,s);putu(b,&o,v);b[o++]='\n';b[o]=0;OutputDebugStringA(b);}

static CONDITION_VARIABLE g_cv;
static CRITICAL_SECTION   g_cs;
static volatile int g_work = 0, g_done = 0, g_stop = 0;

static DWORD WINAPI worker(LPVOID p){ (void)p;
    dbg("CV/worker: start");
    for(;;){
        EnterCriticalSection(&g_cs);
        while (g_work == 0 && !g_stop)
            SleepConditionVariableCS(&g_cv, &g_cs, INFINITE); // park until work queued
        if (g_stop && g_work == 0){ LeaveCriticalSection(&g_cs); break; }
        g_work--; g_done++;
        LeaveCriticalSection(&g_cs);
        dbg2("CV/worker: processed item, done=", (unsigned)g_done);
    }
    dbg("CV/worker: exit");
    return 0;
}

int main(void){
    dbg("CVCHECK: start");
    InitializeConditionVariable(&g_cv);
    InitializeCriticalSection(&g_cs);
    HANDLE th = CreateThread(NULL,0,worker,NULL,0,NULL);
    for (int i=0;i<5;i++){
        EnterCriticalSection(&g_cs); g_work++; LeaveCriticalSection(&g_cs);
        WakeConditionVariable(&g_cv);   // hand the item to the parked worker
        Sleep(30);                       // let the worker run
    }
    Sleep(100);
    EnterCriticalSection(&g_cs); g_stop = 1; LeaveCriticalSection(&g_cs);
    WakeAllConditionVariable(&g_cv);
    WaitForSingleObject(th, 2000);
    dbg2("CVCHECK: DONE processed=", (unsigned)g_done);
    dbg(g_done == 5 ? "CVCHECK: VERDICT PASS" : "CVCHECK: VERDICT FAIL");
    return 0;
}
