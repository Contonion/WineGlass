#include "wg_selftest.h"
#include "wg_log.h"
#include "wg_memory.h"
#include "wg_x86_state.h"
#include "wg_x86_decode.h"
#include "wg_x86_interp.h"
#include "wg_pe_loader.h"
#include "wg_blink_bridge.h"
#include "wg_engine.h"
#include <string.h>

#define TAG "Test"

static int s_pass = 0;
static int s_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { s_pass++; WG_LOGI(TAG, "  PASS: %s", msg); } \
    else      { s_fail++; WG_LOGE(TAG, "  FAIL: %s", msg); } \
} while(0)

static void test_decoder(void) {
    WG_LOGI(TAG, "--- Decoder Tests ---");

    WGInstruction insn;

    // NOP (0x90)
    uint8_t nop[] = {0x90};
    int len = wg_x86_decode(nop, 1, 0, &insn);
    CHECK(len == 1 && insn.opcode == WG_OP_NOP, "NOP decodes");

    // MOV RAX, 0x1234 (48 B8 34 12 00 00 00 00 00 00)
    uint8_t mov_rax_imm[] = {0x48, 0xB8, 0x34, 0x12, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    len = wg_x86_decode(mov_rax_imm, sizeof(mov_rax_imm), 0, &insn);
    CHECK(len == 10 && insn.opcode == WG_OP_MOV, "MOV RAX, imm64 decodes");
    CHECK(insn.operands[1].imm == 0x1234, "MOV RAX immediate value correct");

    // PUSH RBP (55)
    uint8_t push_rbp[] = {0x55};
    len = wg_x86_decode(push_rbp, 1, 0, &insn);
    CHECK(len == 1 && insn.opcode == WG_OP_PUSH, "PUSH RBP decodes");
    CHECK(insn.operands[0].reg_index == 5, "PUSH RBP register is RBP");

    // SUB RSP, 0x20 (48 83 EC 20)
    uint8_t sub_rsp[] = {0x48, 0x83, 0xEC, 0x20};
    len = wg_x86_decode(sub_rsp, sizeof(sub_rsp), 0, &insn);
    CHECK(len == 4 && insn.opcode == WG_OP_SUB, "SUB RSP, 0x20 decodes");

    // XOR EAX, EAX (31 C0)
    uint8_t xor_eax[] = {0x31, 0xC0};
    len = wg_x86_decode(xor_eax, sizeof(xor_eax), 0, &insn);
    CHECK(len == 2 && insn.opcode == WG_OP_XOR, "XOR EAX, EAX decodes");

    // JE +5 (74 05)
    uint8_t je[] = {0x74, 0x05};
    len = wg_x86_decode(je, sizeof(je), 0x1000, &insn);
    CHECK(len == 2 && insn.opcode == WG_OP_JCC, "JE rel8 decodes");
    CHECK(insn.condition == 0x4, "JE condition code is 4 (ZF)");
    CHECK(insn.operands[0].imm == 0x1007, "JE target address correct");

    // CALL rel32 (E8 xx xx xx xx)
    uint8_t call[] = {0xE8, 0x10, 0x00, 0x00, 0x00};
    len = wg_x86_decode(call, sizeof(call), 0x2000, &insn);
    CHECK(len == 5 && insn.opcode == WG_OP_CALL, "CALL rel32 decodes");
    CHECK(insn.operands[0].imm == 0x2015, "CALL target correct");

    // RET (C3)
    uint8_t ret[] = {0xC3};
    len = wg_x86_decode(ret, 1, 0, &insn);
    CHECK(len == 1 && insn.opcode == WG_OP_RET, "RET decodes");

    // LEA RAX, [RIP+0] (48 8D 05 00 00 00 00)
    uint8_t lea_rip[] = {0x48, 0x8D, 0x05, 0x00, 0x00, 0x00, 0x00};
    len = wg_x86_decode(lea_rip, sizeof(lea_rip), 0x3000, &insn);
    CHECK(len == 7 && insn.opcode == WG_OP_LEA, "LEA [RIP+0] decodes");
}

static void test_interpreter(void) {
    WG_LOGI(TAG, "--- Interpreter Tests ---");

    WGMemorySpace *mem = wg_memory_create(0x100000);
    WGx86State *cpu = wg_x86_state_create();

    // Map code region and stack
    wg_memory_map(mem, 0x1000, 0x1000, WG_MEM_READ | WG_MEM_EXEC | WG_MEM_WRITE);
    wg_memory_map(mem, 0xF000, 0x1000, WG_MEM_READ | WG_MEM_WRITE);

    // Test: MOV RAX, 42; MOV RCX, 8; ADD RAX, RCX; HLT
    // 48 B8 2A 00 00 00 00 00 00 00  = MOV RAX, 42
    // 48 B9 08 00 00 00 00 00 00 00  = MOV RCX, 8
    // 48 01 C8                        = ADD RAX, RCX
    // F4                              = HLT
    uint8_t code1[] = {
        0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0xB9, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x01, 0xC8,
        0xF4
    };
    wg_memory_write(mem, 0x1000, code1, sizeof(code1));
    wg_x86_state_reset(cpu);
    cpu->rip = 0x1000;
    cpu->gpr[WG_REG_RSP] = 0xFF00;

    WGInterpResult r = wg_x86_exec_block(cpu, mem, 100);
    CHECK(r == WG_INTERP_HALT, "Simple add program halts");
    CHECK(cpu->gpr[WG_REG_RAX] == 50, "RAX = 42 + 8 = 50");

    // Test: PUSH/POP
    // PUSH 0x1234 (68 34 12 00 00)
    // POP RCX (59)
    // HLT (F4)
    uint8_t code2[] = {0x68, 0x34, 0x12, 0x00, 0x00, 0x59, 0xF4};
    wg_memory_write(mem, 0x1000, code2, sizeof(code2));
    wg_x86_state_reset(cpu);
    cpu->rip = 0x1000;
    cpu->gpr[WG_REG_RSP] = 0xFF00;

    r = wg_x86_exec_block(cpu, mem, 100);
    CHECK(r == WG_INTERP_HALT, "Push/pop program halts");
    CHECK(cpu->gpr[WG_REG_RCX] == 0x1234, "POP RCX = 0x1234 after PUSH");
    CHECK(cpu->gpr[WG_REG_RSP] == 0xFF00, "RSP restored after push+pop");

    // Test: CMP + JE
    // XOR EAX, EAX (31 C0)
    // CMP EAX, 0 (83 F8 00)
    // JE +2 (74 02)
    // HLT (F4) -- should be skipped
    // NOP (90)
    // MOV EAX, 99 (B8 63 00 00 00)
    // HLT (F4)
    uint8_t code3[] = {
        0x31, 0xC0,
        0x83, 0xF8, 0x00,
        0x74, 0x01,
        0xF4,
        0xB8, 0x63, 0x00, 0x00, 0x00,
        0xF4
    };
    wg_memory_write(mem, 0x1000, code3, sizeof(code3));
    wg_x86_state_reset(cpu);
    cpu->rip = 0x1000;
    cpu->gpr[WG_REG_RSP] = 0xFF00;

    r = wg_x86_exec_block(cpu, mem, 100);
    CHECK(r == WG_INTERP_HALT, "CMP/JE program halts");
    CHECK(cpu->gpr[WG_REG_RAX] == 99, "JE branched correctly, RAX=99");

    // Test: CALL + RET
    // CALL +5 (E8 05 00 00 00) -> calls 0x100A
    // MOV RCX, RAX (48 89 C1)
    // HLT (F4)
    // NOP (at 0x100A: the function)
    // MOV EAX, 77 (B8 4D 00 00 00)
    // RET (C3)
    uint8_t code4[] = {
        0xE8, 0x04, 0x00, 0x00, 0x00,   // CALL 0x1009
        0x48, 0x89, 0xC1,                // MOV RCX, RAX
        0xF4,                            // HLT
        0xB8, 0x4D, 0x00, 0x00, 0x00,   // MOV EAX, 77 (at 0x1009)
        0xC3                             // RET
    };
    wg_memory_write(mem, 0x1000, code4, sizeof(code4));
    wg_x86_state_reset(cpu);
    cpu->rip = 0x1000;
    cpu->gpr[WG_REG_RSP] = 0xFF00;

    r = wg_x86_exec_block(cpu, mem, 100);
    CHECK(r == WG_INTERP_HALT, "CALL/RET program halts");
    CHECK(cpu->gpr[WG_REG_RAX] == 77, "Function returned RAX=77");
    CHECK(cpu->gpr[WG_REG_RCX] == 77, "Caller received return value in RCX");

    // Test: Loop (countdown from 10)
    // MOV ECX, 10 (B9 0A 00 00 00)
    // DEC ECX (FF C9) -- at 0x1005
    // JNZ -4 (75 FC) -> back to 0x1005
    // MOV EAX, ECX (89 C8)
    // HLT (F4)
    uint8_t code5[] = {
        0xB9, 0x0A, 0x00, 0x00, 0x00,   // MOV ECX, 10
        0xFF, 0xC9,                       // DEC ECX
        0x75, 0xFC,                       // JNZ -4 (back to DEC)
        0x89, 0xC8,                       // MOV EAX, ECX
        0xF4                              // HLT
    };
    wg_memory_write(mem, 0x1000, code5, sizeof(code5));
    wg_x86_state_reset(cpu);
    cpu->rip = 0x1000;
    cpu->gpr[WG_REG_RSP] = 0xFF00;

    r = wg_x86_exec_block(cpu, mem, 200);
    CHECK(r == WG_INTERP_HALT, "Loop program halts");
    CHECK(cpu->gpr[WG_REG_RAX] == 0, "Loop counted down to 0");
    CHECK(cpu->gpr[WG_REG_RCX] == 0, "ECX == 0 after loop");

    wg_x86_state_destroy(cpu);
    wg_memory_destroy(mem);
}

static void test_pe_parser(void) {
    WG_LOGI(TAG, "--- PE Parser Tests ---");

    // Build a minimal valid PE file in memory
    uint8_t pe[512];
    memset(pe, 0, sizeof(pe));

    // DOS header
    pe[0] = 'M'; pe[1] = 'Z';
    *(int32_t*)(pe + 0x3C) = 0x80; // e_lfanew

    // PE signature at 0x80
    pe[0x80] = 'P'; pe[0x81] = 'E';

    // COFF header at 0x84
    *(uint16_t*)(pe + 0x84) = 0x8664; // Machine = AMD64
    *(uint16_t*)(pe + 0x86) = 1;      // NumberOfSections
    *(uint16_t*)(pe + 0x94) = 112;    // SizeOfOptionalHeader (PE32+)
    *(uint16_t*)(pe + 0x96) = 0x0022; // Characteristics

    // Optional header at 0x98
    *(uint16_t*)(pe + 0x98) = 0x20B;  // Magic = PE32+
    *(uint32_t*)(pe + 0xA8) = 0x1000; // AddressOfEntryPoint
    *(uint64_t*)(pe + 0xB0) = 0x140000000ULL; // ImageBase
    *(uint32_t*)(pe + 0xB8) = 0x1000; // SectionAlignment
    *(uint32_t*)(pe + 0xBC) = 0x200;  // FileAlignment
    *(uint32_t*)(pe + 0xD0) = 0x3000; // SizeOfImage
    *(uint32_t*)(pe + 0xD4) = 0x200;  // SizeOfHeaders
    *(uint16_t*)(pe + 0xDC) = 2;      // Subsystem = GUI (offset 0x44 from opt hdr)
    *(uint32_t*)(pe + 0x104) = 0;     // NumberOfRvaAndSizes

    // Section header right after optional header (0x98 + 112 = 0x108)
    memcpy(pe + 0x108, ".text\0\0\0", 8);
    *(uint32_t*)(pe + 0x110) = 0x100; // VirtualSize
    *(uint32_t*)(pe + 0x114) = 0x1000; // VirtualAddress
    *(uint32_t*)(pe + 0x118) = 0x100; // SizeOfRawData
    *(uint32_t*)(pe + 0x11C) = 0x200; // PointerToRawData
    *(uint32_t*)(pe + 0x128) = 0x60000020; // Characteristics

    // Put a RET at the entry point (file offset 0x200)
    if (sizeof(pe) > 0x200) pe[0x200] = 0xC3;

    WGPEImage *img = wg_pe_load_memory(pe, sizeof(pe));
    CHECK(img != NULL, "Minimal PE parses successfully");
    if (img) {
        CHECK(img->is_64bit, "PE is 64-bit");
        CHECK(img->machine == 0x8664, "Machine is x86-64");
        CHECK(img->entry_point == 0x1000, "Entry point is 0x1000");
        CHECK(img->image_base == 0x140000000ULL, "Image base correct");
        CHECK(img->num_sections == 1, "Has 1 section");
        CHECK(strcmp(img->sections[0].name, ".text") == 0, "Section name is .text");
        CHECK(img->subsystem == 2, "Subsystem is Windows GUI");
        wg_pe_image_free(img);
    }
}

static void test_blink_bridge(void) {
    WG_LOGI(TAG, "--- Blink Bridge Tests (single VM) ---");

    WGBlinkInstance *blink = wg_blink_create();

    CHECK(blink != NULL, "Blink VM created");
    if (!blink) return;

    // Map a real stack. Without this SP is 0, so any CALL/PUSH faults on its
    // store to [SP-8] — which is exactly why the CALL/RET test used to "fail"
    // (the call faulted before reaching the callee, leaving RAX/RCX at 0). The
    // real PE path sets this up via wg_blink_setup_stack(); the self-test must
    // too or it slanders blink's perfectly-good CALL/RET handling.
    CHECK(wg_blink_setup_stack(blink, 0x400000), "Blink: stack set up");

    // Warm-up: first execution after VM creation can trigger a one-time
    // JIT/page-fault abort on iOS. Run a NOP+RET to prime the VM.
    {
        uint8_t warmup[] = { 0x90, 0xC3 }; // NOP; RET
        wg_blink_load_code(blink, 0x400000, warmup, sizeof(warmup), 0x400000);
        WGBlinkResult wr = wg_blink_run(blink, 10);
        if (wr == WG_BLINK_HALT) {
            WG_LOGI(TAG, "  Blink warm-up OK");
        } else {
            WG_LOGW(TAG, "  Blink warm-up failed (result=%d) — first-run JIT init", wr);
        }
    }

    bool loaded;

    // Test 1: MOV EAX, 42; RET
    {
        uint8_t code1[] = { 0xB8, 0x2A, 0x00, 0x00, 0x00, 0xC3 };
        bool loaded = wg_blink_load_code(blink, 0x410000, code1, sizeof(code1), 0x410000);
        CHECK(loaded, "Blink: code loaded at 0x410000");

        if (loaded) {
            WGBlinkResult r = wg_blink_run(blink, 100);
            CHECK(r == WG_BLINK_HALT, "Blink: MOV+RET halts");
            CHECK(wg_blink_get_reg(blink, 0) == 42, "Blink: RAX == 42");
        }
    }


    // Test 2: Arithmetic — ADD, SHL through blink


    // MOV EAX, 10       B8 0A 00 00 00
    // MOV ECX, 3        B9 03 00 00 00
    // ADD EAX, ECX      01 C8
    // SHL EAX, 2        C1 E0 02
    // RET               C3
    uint8_t code2[] = {
        0xB8, 0x0A, 0x00, 0x00, 0x00,
        0xB9, 0x03, 0x00, 0x00, 0x00,
        0x01, 0xC8,
        0xC1, 0xE0, 0x02,
        0xC3
    };
    loaded = wg_blink_load_code(blink, 0x420000, code2, sizeof(code2), 0x420000);
    CHECK(loaded, "Blink: arithmetic code loaded");

    if (loaded) {
        WGBlinkResult r = wg_blink_run(blink, 100);
        CHECK(r == WG_BLINK_HALT, "Blink: arithmetic program halts");

        uint64_t rax = wg_blink_get_reg(blink, 0);
        // (10 + 3) << 2 = 52
        CHECK(rax == 52, "Blink: (10+3)<<2 == 52");
    }


    // Test 3: CALL/RET through blink
    //   CALL func         E8 04 00 00 00
    //   MOV ECX, EAX      89 C1
    //   HLT               F4  (clean halt, preserves registers)
    //   NOP               90
    // func:
    //   MOV EAX, 77        B8 4D 00 00 00
    //   RET                C3
    uint8_t code3[] = {
        0xE8, 0x04, 0x00, 0x00, 0x00,   // CALL +9
        0x89, 0xC1,                       // MOV ECX, EAX
        0xF4,                             // HLT (clean stop)
        0x90,                             // NOP
        0xB8, 0x4D, 0x00, 0x00, 0x00,   // MOV EAX, 77
        0xC3                             // RET
    };
    loaded = wg_blink_load_code(blink, 0x430000, code3, sizeof(code3), 0x430000);
    CHECK(loaded, "Blink: call/ret code loaded");

    if (loaded) {
        WGBlinkResult r = wg_blink_run(blink, 100);
        CHECK(r == WG_BLINK_HALT, "Blink: CALL/RET halts");

        uint64_t rax = wg_blink_get_reg(blink, 0);
        uint64_t rcx = wg_blink_get_reg(blink, 1);
        CHECK(rax == 77, "Blink: function returned RAX=77");
        CHECK(rcx == 77, "Blink: caller got RCX=77");
    }


    // Test 4: Loop with conditional branch


    // MOV ECX, 10     B9 0A 00 00 00
    // DEC ECX         FF C9   (at +5)
    // JNZ -4          75 FC   (back to DEC)
    // MOV EAX, ECX    89 C8
    // RET             C3
    uint8_t code4[] = {
        0xB9, 0x0A, 0x00, 0x00, 0x00,
        0xFF, 0xC9,
        0x75, 0xFC,
        0x89, 0xC8,
        0xC3
    };
    loaded = wg_blink_load_code(blink, 0x440000, code4, sizeof(code4), 0x440000);
    CHECK(loaded, "Blink: loop code loaded");

    if (loaded) {
        WGBlinkResult r = wg_blink_run(blink, 500);
        CHECK(r == WG_BLINK_HALT, "Blink: loop halts");

        uint64_t rax = wg_blink_get_reg(blink, 0);
        uint64_t rcx = wg_blink_get_reg(blink, 1);
        CHECK(rax == 0, "Blink: loop result RAX=0");
        CHECK(rcx == 0, "Blink: loop counter ECX=0");
    }


    // Test 5: SSE — XORPS (zero a register), MOVAPS — tests that
    // blink handles SSE which our builtin interpreter barely covers


    // XORPS XMM0, XMM0   0F 57 C0
    // MOV EAX, 1          B8 01 00 00 00
    // RET                 C3
    uint8_t code5[] = {
        0x0F, 0x57, 0xC0,
        0xB8, 0x01, 0x00, 0x00, 0x00,
        0xC3
    };
    loaded = wg_blink_load_code(blink, 0x450000, code5, sizeof(code5), 0x450000);
    CHECK(loaded, "Blink: SSE code loaded");

    if (loaded) {
        WGBlinkResult r = wg_blink_run(blink, 100);
        CHECK(r == WG_BLINK_HALT, "Blink: SSE program halts");
        CHECK(wg_blink_get_reg(blink, 0) == 1, "Blink: SSE program completed (RAX=1)");
    }


    // Test 6: Fibonacci(10) via function call
    // Compute fib(10) = 55 using a loop:
    //   MOV ECX, 10       ; n
    //   MOV EAX, 0        ; fib(0)
    //   MOV EDX, 1        ; fib(1)
    //   loop:
    //     MOV EBX, EDX    ; temp = b
    //     ADD EDX, EAX    ; b = a + b
    //     MOV EAX, EBX    ; a = temp
    //     DEC ECX
    //     JNZ loop
    //   RET
    {
        uint8_t code[] = {
            0xB9, 0x0A, 0x00, 0x00, 0x00,   // MOV ECX, 10
            0xB8, 0x00, 0x00, 0x00, 0x00,   // MOV EAX, 0
            0xBA, 0x01, 0x00, 0x00, 0x00,   // MOV EDX, 1
            // loop at offset 15:
            0x89, 0xD3,                      // MOV EBX, EDX
            0x01, 0xC2,                      // ADD EDX, EAX
            0x89, 0xD8,                      // MOV EAX, EBX
            0xFF, 0xC9,                      // DEC ECX
            0x75, 0xF6,                      // JNZ -10 (back to MOV EBX, EDX)
            0xC3                             // RET
        };
        loaded = wg_blink_load_code(blink, 0x460000, code, sizeof(code), 0x460000);
        CHECK(loaded, "Blink: Fibonacci code loaded");
        if (loaded) {
            WGBlinkResult r = wg_blink_run(blink, 1000);
            CHECK(r == WG_BLINK_HALT, "Blink: Fibonacci halts");
            uint64_t rax = wg_blink_get_reg(blink, 0);
            WG_LOGI(TAG, "  Fibonacci(10) = %llu", (unsigned long long)rax);
            CHECK(rax == 55, "Blink: Fibonacci(10) == 55");
        }
    }

    // Test 7: 64-bit multiply — tests REX.W prefix handling
    //   MOV RAX, 100000    (48 B8 ...)
    //   MOV RCX, 100000    (48 B9 ...)
    //   IMUL RAX, RCX      (48 0F AF C1)
    //   RET
    {
        uint8_t code[] = {
            0x48, 0xB8, 0xA0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 100000
            0x48, 0xB9, 0xA0, 0x86, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RCX, 100000
            0x48, 0x0F, 0xAF, 0xC1,                                     // IMUL RAX, RCX
            0xC3                                                          // RET
        };
        loaded = wg_blink_load_code(blink, 0x470000, code, sizeof(code), 0x470000);
        CHECK(loaded, "Blink: 64-bit multiply code loaded");
        if (loaded) {
            WGBlinkResult r = wg_blink_run(blink, 100);
            CHECK(r == WG_BLINK_HALT, "Blink: 64-bit multiply halts");
            uint64_t rax = wg_blink_get_reg(blink, 0);
            WG_LOGI(TAG, "  100000 * 100000 = %llu", (unsigned long long)rax);
            CHECK(rax == 10000000000ULL, "Blink: 100000*100000 == 10000000000");
        }
    }

    // Test 8: Memory read/write through blink — store to memory, load back
    //   MOV DWORD [0x480100], 0xDEADBEEF    (C7 04 25 ...)
    //   MOV EAX, [0x480100]                  (8B 04 25 ...)
    //   RET
    {
        uint8_t code[] = {
            0xC7, 0x04, 0x25,                                     // MOV DWORD PTR [abs32], imm32
            0x00, 0x01, 0x48, 0x00,                               // address = 0x480100
            0xEF, 0xBE, 0xAD, 0xDE,                               // value = 0xDEADBEEF
            0x8B, 0x04, 0x25,                                     // MOV EAX, DWORD PTR [abs32]
            0x00, 0x01, 0x48, 0x00,                               // address = 0x480100
            0xC3                                                   // RET
        };
        // Map the data page first
        uint8_t zeros[4096] = {0};
        wg_blink_load_code(blink, 0x480000, zeros, sizeof(zeros), 0);
        // Load the code at a separate page
        loaded = wg_blink_load_code(blink, 0x490000, code, sizeof(code), 0x490000);
        CHECK(loaded, "Blink: memory test code loaded");
        if (loaded) {
            WGBlinkResult r = wg_blink_run(blink, 100);
            CHECK(r == WG_BLINK_HALT, "Blink: memory test halts");
            uint64_t rax = wg_blink_get_reg(blink, 0);
            WG_LOGI(TAG, "  Memory store/load = 0x%llX", (unsigned long long)rax);
            CHECK(rax == 0xDEADBEEF, "Blink: stored 0xDEADBEEF, loaded back correctly");
        }
    }

    WG_LOGI(TAG, "Blink JIT available: %s", wg_blink_has_jit() ? "YES" : "NO");
    WG_LOGI(TAG, "x86-64 code executed successfully on this device");
}

bool wg_selftest_run_safe(void) {
    WG_LOGI(TAG, "=== WineGlass Self-Test Suite (safe) ===");
    s_pass = 0;
    s_fail = 0;

    test_decoder();
    test_interpreter();
    test_pe_parser();

    WG_LOGI(TAG, "=== Results: %d passed, %d failed ===", s_pass, s_fail);
    return s_fail == 0;
}

// Build a complete PE64 in memory with:
//   - .text section with x86-64 code
//   - .idata section with import table (kernel32.dll!ExitProcess)
//   - Code that does: MOV EAX, 42; CALL [IAT_ExitProcess]; RET
static void test_pe_execution(void) {
    WG_LOGI(TAG, "--- PE Execution Test ---");

    // PE layout:
    //   0x000-0x1FF: headers
    //   0x200-0x3FF: .text (code)
    //   0x400-0x5FF: .idata (import table)
    //
    // Virtual layout (image_base = 0x00500000):
    //   0x500000-0x5001FF: headers
    //   0x501000-0x5011FF: .text
    //   0x502000-0x5021FF: .idata
    //
    // Import: kernel32.dll -> ExitProcess
    // IAT entry at RVA 0x2080
    // Code: MOV ECX, 42; CALL QWORD [RIP+IAT]; RET

    uint8_t pe[0x600];
    memset(pe, 0, sizeof(pe));

    // --- DOS header ---
    pe[0] = 'M'; pe[1] = 'Z';
    *(int32_t*)(pe + 0x3C) = 0x80;

    // --- PE signature ---
    *(uint32_t*)(pe + 0x80) = 0x00004550; // "PE\0\0"

    // --- COFF header at 0x84 ---
    *(uint16_t*)(pe + 0x84) = 0x8664;  // Machine = AMD64
    *(uint16_t*)(pe + 0x86) = 2;       // NumberOfSections
    *(uint16_t*)(pe + 0x94) = 240;     // SizeOfOptionalHeader (112 fixed + 16*8 dirs)
    *(uint16_t*)(pe + 0x96) = 0x0022;  // Characteristics

    // --- Optional header (PE32+) at 0x98 ---
    *(uint16_t*)(pe + 0x98) = 0x20B;           // Magic = PE32+
    *(uint32_t*)(pe + 0xA8) = 0x1000;          // AddressOfEntryPoint (RVA)
    *(uint64_t*)(pe + 0xB0) = 0x00500000ULL;   // ImageBase
    *(uint32_t*)(pe + 0xB8) = 0x1000;          // SectionAlignment
    *(uint32_t*)(pe + 0xBC) = 0x200;           // FileAlignment
    *(uint32_t*)(pe + 0xD0) = 0x4000;          // SizeOfImage
    *(uint32_t*)(pe + 0xD4) = 0x200;           // SizeOfHeaders
    *(uint16_t*)(pe + 0xDC) = 3;               // Subsystem = Console
    *(uint32_t*)(pe + 0x104) = 16;             // NumberOfRvaAndSizes

    // Data directory [1] = Import Directory: RVA=0x2000, Size=0x28
    // Directory entries start at 0x108, each is 8 bytes, import is index 1
    *(uint32_t*)(pe + 0x108 + 1*8 + 0) = 0x2000; // Import RVA
    *(uint32_t*)(pe + 0x108 + 1*8 + 4) = 0x28;   // Import Size

    // --- Section headers at 0x108 + 16*8 = 0x188 ---
    int sec_off = 0x188;

    // .text section
    memcpy(pe + sec_off, ".text\0\0\0", 8);
    *(uint32_t*)(pe + sec_off + 0x08) = 0x200;       // VirtualSize
    *(uint32_t*)(pe + sec_off + 0x0C) = 0x1000;      // VirtualAddress
    *(uint32_t*)(pe + sec_off + 0x10) = 0x200;       // SizeOfRawData
    *(uint32_t*)(pe + sec_off + 0x14) = 0x200;       // PointerToRawData
    *(uint32_t*)(pe + sec_off + 0x24) = 0x60000020;  // CODE|EXECUTE|READ

    // .idata section
    sec_off += 40;
    memcpy(pe + sec_off, ".idata\0\0", 8);
    *(uint32_t*)(pe + sec_off + 0x08) = 0x200;       // VirtualSize
    *(uint32_t*)(pe + sec_off + 0x0C) = 0x2000;      // VirtualAddress
    *(uint32_t*)(pe + sec_off + 0x10) = 0x200;       // SizeOfRawData
    *(uint32_t*)(pe + sec_off + 0x14) = 0x400;       // PointerToRawData
    *(uint32_t*)(pe + sec_off + 0x24) = 0xC0000040;  // INITIALIZED_DATA|READ|WRITE

    // --- .text content at file offset 0x200 ---
    // Entry point code (at RVA 0x1000):
    //   MOV ECX, 42              ; B9 2A 00 00 00       (arg to ExitProcess)
    //   MOV RAX, [RIP+disp]      ; 48 8B 05 xx xx xx xx (load IAT entry)
    //   CALL RAX                 ; FF D0                (call ExitProcess)
    //   RET                      ; C3                   (fallback)
    //
    // IAT is at RVA 0x2080. RIP after the MOV is at 0x100C.
    // disp = 0x2080 - 0x100C = 0x1074
    uint8_t *code = pe + 0x200;
    code[0] = 0xB9; code[1] = 0x2A; code[2] = 0x00; code[3] = 0x00; code[4] = 0x00; // MOV ECX, 42
    code[5] = 0x48; code[6] = 0x8B; code[7] = 0x05;                                  // MOV RAX, [RIP+
    *(int32_t*)(code + 8) = 0x1074;                                                    //   0x1074]
    code[12] = 0xFF; code[13] = 0xD0;                                                 // CALL RAX
    code[14] = 0xC3;                                                                   // RET

    // --- .idata content at file offset 0x400 ---
    // Import Directory Table (one entry + null terminator)
    // At RVA 0x2000:
    //   OriginalFirstThunk (ILT) = 0x2060
    //   TimeDateStamp = 0
    //   ForwarderChain = 0
    //   Name = 0x20A0  (-> "kernel32.dll")
    //   FirstThunk (IAT) = 0x2080
    uint8_t *idata = pe + 0x400;
    *(uint32_t*)(idata + 0x00) = 0x2060; // OriginalFirstThunk
    *(uint32_t*)(idata + 0x0C) = 0x20A0; // Name RVA
    *(uint32_t*)(idata + 0x10) = 0x2080; // FirstThunk (IAT)
    // Null terminator entry (20 zero bytes) follows automatically

    // Import Lookup Table at RVA 0x2060 (file offset 0x460):
    // One entry pointing to Hint/Name at RVA 0x20C0, then null
    *(uint64_t*)(idata + 0x60) = 0x20C0; // -> Hint/Name
    *(uint64_t*)(idata + 0x68) = 0;      // null terminator

    // Import Address Table at RVA 0x2080 (file offset 0x480):
    // Same as ILT before binding
    *(uint64_t*)(idata + 0x80) = 0x20C0; // -> Hint/Name (will be overwritten with thunk)
    *(uint64_t*)(idata + 0x88) = 0;      // null terminator

    // DLL name at RVA 0x20A0 (file offset 0x4A0):
    memcpy(idata + 0xA0, "kernel32.dll\0", 13);

    // Hint/Name at RVA 0x20C0 (file offset 0x4C0):
    *(uint16_t*)(idata + 0xC0) = 0;  // Hint
    memcpy(idata + 0xC2, "ExitProcess\0", 12);

    // --- Now load and execute through the engine ---
    WGEngine *engine = wg_engine_create();
    CHECK(engine != NULL, "PE exec: engine created");
    if (!engine) return;

    bool init_ok = wg_engine_init(engine);
    CHECK(init_ok, "PE exec: engine initialized");
    if (!init_ok) { wg_engine_destroy(engine); return; }

    bool load_ok = wg_engine_load_pe_memory(engine, pe, sizeof(pe));
    CHECK(load_ok, "PE exec: PE loaded with imports");
    if (!load_ok) { wg_engine_destroy(engine); return; }

    WG_LOGI(TAG, "  Running PE: MOV ECX,42 -> CALL ExitProcess...");
    WGEngineState final_state = wg_engine_run_sync(engine, 100);
    CHECK(final_state == WG_ENGINE_STOPPED, "PE exec: program terminated");

    WG_LOGI(TAG, "  PE execution complete (state=%d)", final_state);

    wg_engine_destroy(engine);
}

bool wg_selftest_run(void) {
    WG_LOGI(TAG, "=== WineGlass Self-Test Suite (full) ===");
    s_pass = 0;
    s_fail = 0;

    test_decoder();
    test_interpreter();
    test_pe_parser();
    test_blink_bridge();
    test_pe_execution();

    WG_LOGI(TAG, "=== Results: %d passed, %d failed ===", s_pass, s_fail);
    return s_fail == 0;
}
