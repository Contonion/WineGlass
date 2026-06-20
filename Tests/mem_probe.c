// WineGlass memory conformance probe. ALU probes all passed, so this targets
// what LZMA stresses: 16-bit memory ops, indexed addressing, rep movs/stos,
// unaligned access, and — crucially — a LARGE guest allocation (like LZMA's
// 8MB dictionary) that may exceed blink's 16MB physical backing (kRealSize).
// Reports a pass/fail bitmask via ExitProcess.
//
//   i686-w64-mingw32-gcc -O0 -ffreestanding -nostdlib -fno-builtin -e _start_ \
//     -Wl,--subsystem,windows -o WGMem.exe mem_probe.c -lkernel32

#include <windows.h>

static unsigned small_tests(unsigned char *b) {
    unsigned m = 0;
    volatile unsigned short *u16 = (volatile unsigned short *)b;
    volatile unsigned *u32 = (volatile unsigned *)b;
    volatile unsigned char *u8 = b;

    // 0: 16-bit store/load
    u16[0] = 0x1234;
    m |= (u16[0] == 0x1234u) << 0;

    // 1: 16-bit indexed [base + idx*2]
    u16[100] = 0xABCD; u16[101] = 0x0001;
    m |= (u16[100] == 0xABCDu && u16[101] == 0x0001u) << 1;

    // 2: 32-bit indexed [base + idx*4]
    u32[50] = 0xDEADBEEFu;
    m |= (u32[50] == 0xDEADBEEFu) << 2;

    // 3: byte store/load
    u8[7] = 0xAB;
    m |= (u8[7] == 0xABu) << 3;

    // 4: LZMA probability update on a UInt16 in memory
    u16[200] = 1000;
    { unsigned p = u16[200]; p += (2048 - p) >> 5; u16[200] = (unsigned short)p; }
    m |= (u16[200] == 1032u) << 4;

    // 5: unaligned 32-bit access
    *(volatile unsigned *)(b + 1) = 0xCAFEBABEu;
    m |= (*(volatile unsigned *)(b + 1) == 0xCAFEBABEu) << 5;

    // 6: rep movsb (memcpy — LZMA dictionary copy)
    for (int i = 0; i < 16; i++) u8[0x100 + i] = (unsigned char)(i * 7 + 1);
    __asm__ volatile("cld\n\trep movsb"
                     : : "S"(b + 0x100), "D"(b + 0x200), "c"(16) : "memory");
    { int ok = 1; for (int i = 0; i < 16; i++)
        if (u8[0x200 + i] != (unsigned char)(i * 7 + 1)) ok = 0;
      m |= ok << 6; }

    // 7: rep stosb (memset)
    __asm__ volatile("cld\n\trep stosb"
                     : : "D"(b + 0x300), "a"(0xCC), "c"(32) : "memory");
    { int ok = 1; for (int i = 0; i < 32; i++) if (u8[0x300 + i] != 0xCC) ok = 0;
      m |= ok << 7; }

    return m;
}

void _start_(void) {
    unsigned m = 0;

    // Small-buffer memory tests at the guest heap (~0x10000000, where LZMA's
    // dictionary also lives).
    unsigned char *b = (unsigned char *)GlobalAlloc(0, 0x10000);
    if (b) {
        m |= 1u << 31;          // bit31: small alloc succeeded
        m |= small_tests(b);    // bits 0..7
    }

    // LARGE allocation like LZMA's dictionary. If this exceeds blink's 16MB
    // physical backing, writes/reads will corrupt.
    unsigned long sz = 12u * 1024 * 1024;   // 12 MB
    volatile unsigned *big = (volatile unsigned *)GlobalAlloc(0, sz);
    if (big) {
        m |= 1u << 8;           // bit8: large alloc returned non-null
        unsigned words = sz / 4;
        // Write a deterministic pattern across every page.
        for (unsigned i = 0; i < words; i += 1024)      // one write per 4KB page
            big[i] = i ^ 0x5A5A5A5Au;
        // Read back and verify.
        int ok = 1;
        for (unsigned i = 0; i < words; i += 1024)
            if (big[i] != (i ^ 0x5A5A5A5Au)) { ok = 0; break; }
        m |= ok << 9;           // bit9: large memory integrity

        // Also hammer the last page specifically.
        big[words - 1] = 0x13572468u;
        m |= (big[words - 1] == 0x13572468u) << 10;  // bit10: end-of-buffer
    }

    ExitProcess(m);
}
