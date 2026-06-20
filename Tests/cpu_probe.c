// WineGlass CPU conformance probe — a minimal 32-bit PE that exercises the
// instruction classes LZMA's range decoder depends on, each with a known
// answer. Reports a pass/fail bitmask via ExitProcess(mask). Bit N set =
// probe N correct. A missing bit pinpoints the instruction blink mis-executes.
//
//   i686-w64-mingw32-gcc -O0 -ffreestanding -nostdlib -fno-builtin -e _start_ \
//     -Wl,--subsystem,windows -o WGProbe.exe cpu_probe.c -lkernel32

#include <windows.h>

#define PROBE(name) static unsigned name(void)

PROBE(p_shrd) { unsigned o;
    __asm__ volatile("movl $0x12345678,%%eax\n\tmovl $0x0000000F,%%ebx\n\t"
                     "shrd $4,%%ebx,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ebx","cc");
    return o == 0xF1234567u; }

PROBE(p_shld) { unsigned o;
    __asm__ volatile("movl $0x12345678,%%eax\n\tmovl $0xF0000000,%%ebx\n\t"
                     "shld $4,%%ebx,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ebx","cc");
    return o == 0x2345678Fu; }

PROBE(p_rol) { unsigned o;
    __asm__ volatile("movl $0x12345678,%%eax\n\troll $8,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 0x34567812u; }

PROBE(p_ror) { unsigned o;
    __asm__ volatile("movl $0x12345678,%%eax\n\trorl $8,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 0x78123456u; }

PROBE(p_bsr) { unsigned o;
    __asm__ volatile("movl $0x00010000,%%eax\n\tbsrl %%eax,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 16; }

PROBE(p_bsf) { unsigned o;
    __asm__ volatile("movl $0x00010000,%%eax\n\tbsfl %%eax,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 16; }

PROBE(p_imul) { unsigned o;
    __asm__ volatile("movl $0x12345,%%eax\n\tmovl $0x10,%%ecx\n\t"
                     "imull %%ecx,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ecx","cc");
    return o == 0x123450u; }

PROBE(p_mul64) { unsigned hi;
    __asm__ volatile("movl $0x10000000,%%eax\n\tmovl $0x10,%%ecx\n\t"
                     "mull %%ecx\n\tmovl %%edx,%0"
                     : "=r"(hi) :: "eax","ecx","edx","cc");
    return hi == 1; }

PROBE(p_adc) { unsigned o;
    __asm__ volatile("stc\n\tmovl $0,%%eax\n\tadcl $0,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 1; }

PROBE(p_sbb) { unsigned o;
    __asm__ volatile("stc\n\tmovl $5,%%eax\n\tsbbl $0,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 4; }

PROBE(p_movzx) { unsigned o;
    __asm__ volatile("movl $0xFFFFFFFF,%%ebx\n\tmovzbl %%bl,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ebx");
    return o == 0xFFu; }

PROBE(p_movsx) { unsigned o;
    __asm__ volatile("movl $0xFFFFFFFF,%%ebx\n\tmovsbl %%bl,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ebx");
    return o == 0xFFFFFFFFu; }

PROBE(p_alwrite) { unsigned o;
    __asm__ volatile("movl $0xFFFFFFFF,%%eax\n\tmovb $0x12,%%al\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax");
    return o == 0xFFFFFF12u; }

PROBE(p_axwrite) { unsigned o;
    __asm__ volatile("movl $0xFFFFFFFF,%%eax\n\tmovw $0x1234,%%ax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax");
    return o == 0xFFFF1234u; }

PROBE(p_bswap) { unsigned o;
    __asm__ volatile("movl $0x12345678,%%eax\n\tbswap %%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax");
    return o == 0x78563412u; }

// LZMA range-decoder core math: bound = (range >> 11) * prob
PROBE(p_lzma_bound) { unsigned o;
    __asm__ volatile("movl $0xFF000000,%%eax\n\tshrl $11,%%eax\n\t"
                     "movl $1024,%%ecx\n\timull %%ecx,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","ecx","cc");
    return o == 0x7F800000u; }

// LZMA normalization: range <<= 8; code = (code<<8) | byte
PROBE(p_lzma_norm) { unsigned o;
    __asm__ volatile("movl $0x00345678,%%eax\n\tshll $8,%%eax\n\t"
                     "orl $0xAB,%%eax\n\tmovl %%eax,%0"
                     : "=r"(o) :: "eax","cc");
    return o == 0x345678ABu; }

void _start_(void) {
    unsigned m = 0;
    m |= p_shrd()       << 0;
    m |= p_shld()       << 1;
    m |= p_rol()        << 2;
    m |= p_ror()        << 3;
    m |= p_bsr()        << 4;
    m |= p_bsf()        << 5;
    m |= p_imul()       << 6;
    m |= p_mul64()      << 7;
    m |= p_adc()        << 8;
    m |= p_sbb()        << 9;
    m |= p_movzx()      << 10;
    m |= p_movsx()      << 11;
    m |= p_alwrite()    << 12;
    m |= p_axwrite()    << 13;
    m |= p_bswap()      << 14;
    m |= p_lzma_bound() << 15;
    m |= p_lzma_norm()  << 16;
    // All-pass = 0x1FFFF (17 bits). ExitProcess code carries the bitmask.
    ExitProcess(m);
}
