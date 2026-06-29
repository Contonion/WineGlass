// wg_writecheck.c — deterministic regression test for the WriteFile 1MB-cap bug.
// Steam's package save fails when WriteFile reports fewer bytes written than
// requested (the engine used to truncate writes to 1MB). This does a single
// WriteFile of 2MB and checks the reported count, then reopens and checks the
// file size. Results are visible in the engine log via the WriteFile handler's
// "WriteFile(0x.., N bytes) -> wrote M" line (printf/CRT stdio is auto-stubbed).
//
// Build: i686-w64-mingw32-gcc -O2 -s -static -o Tests/wg_writecheck.exe Tests/wg_writecheck.c
// Run:   /tmp/wineglass_mac/wineglass_run Tests/wg_writecheck.exe 10
// PASS  = log shows "wrote 2097152" (full) and GetFileSize 2097152.
// FAIL  = "wrote 1048576" (the old 1MB cap) or a SHORT write.

#include <windows.h>

#define WRITE_BYTES (2u * 1024u * 1024u)   // 2 MB, > the old 1 MB cap

int main(void) {
    static unsigned char buf[WRITE_BYTES];
    for (unsigned i = 0; i < WRITE_BYTES; i++) buf[i] = (unsigned char)(i & 0xFF);

    HANDLE h = CreateFileW(L"C:\\writecheck.bin", GENERIC_WRITE, 0, NULL,
                           CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 2;

    DWORD written = 0;
    BOOL ok = WriteFile(h, buf, WRITE_BYTES, &written, NULL);
    CloseHandle(h);

    // Encode the outcome in the exit code so it shows up without stdio:
    //  0 = full write (PASS), 1 = short/truncated write (FAIL), 3 = WriteFile err.
    if (!ok) return 3;
    if (written != WRITE_BYTES) return 1;

    // Reopen and confirm the on-disk size matches.
    HANDLE r = CreateFileW(L"C:\\writecheck.bin", GENERIC_READ, FILE_SHARE_READ,
                           NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (r == INVALID_HANDLE_VALUE) return 4;
    DWORD sz = GetFileSize(r, NULL);
    CloseHandle(r);
    return (sz == WRITE_BYTES) ? 0 : 5;
}
