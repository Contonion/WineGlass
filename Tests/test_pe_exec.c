// End-to-end test: build a minimal PE in memory with actual x86-64 code,
// load it through the engine, and execute it.

#include "wg_log.h"
#include "wg_engine.h"
#include "wg_pe_loader.h"
#include "wg_memory.h"
#include "wg_x86_state.h"
#include "wg_x86_interp.h"
#include "wg_dll_mapper.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static void build_test_pe(const char *path) {
    // Build a minimal PE64 that:
    //   MOV EAX, 42
    //   RET
    uint8_t pe[1024];
    memset(pe, 0, sizeof(pe));

    // DOS header
    pe[0] = 'M'; pe[1] = 'Z';
    *(int32_t*)(pe + 0x3C) = 0x80;

    // PE signature
    pe[0x80] = 'P'; pe[0x81] = 'E';

    // COFF header
    *(uint16_t*)(pe + 0x84) = 0x8664; // AMD64
    *(uint16_t*)(pe + 0x86) = 1;      // 1 section
    *(uint16_t*)(pe + 0x94) = 112;    // optional header size
    *(uint16_t*)(pe + 0x96) = 0x0022; // EXECUTABLE_IMAGE | LARGE_ADDRESS_AWARE

    // Optional header (PE32+)
    *(uint16_t*)(pe + 0x98) = 0x20B;           // Magic
    *(uint32_t*)(pe + 0xA8) = 0x1000;          // AddressOfEntryPoint
    *(uint64_t*)(pe + 0xB0) = 0x00400000ULL;   // ImageBase
    *(uint32_t*)(pe + 0xB8) = 0x1000;          // SectionAlignment
    *(uint32_t*)(pe + 0xBC) = 0x200;           // FileAlignment
    *(uint32_t*)(pe + 0xD0) = 0x3000;          // SizeOfImage
    *(uint32_t*)(pe + 0xD4) = 0x200;           // SizeOfHeaders
    *(uint16_t*)(pe + 0xDC) = 3;               // Subsystem = Console
    *(uint32_t*)(pe + 0x104) = 0;              // NumberOfRvaAndSizes

    // Section header at 0x108
    memcpy(pe + 0x108, ".text\0\0\0", 8);
    *(uint32_t*)(pe + 0x110) = 0x200;          // VirtualSize
    *(uint32_t*)(pe + 0x114) = 0x1000;         // VirtualAddress
    *(uint32_t*)(pe + 0x118) = 0x200;          // SizeOfRawData
    *(uint32_t*)(pe + 0x11C) = 0x200;          // PointerToRawData
    *(uint32_t*)(pe + 0x128) = 0x60000020;     // CODE | EXECUTE | READ

    // Code at file offset 0x200 (VA 0x00401000):
    // B8 2A 00 00 00    MOV EAX, 42
    // 48 89 C1          MOV RCX, RAX   (just to prove more instructions work)
    // 48 C1 E1 01       SHL RCX, 1     (RCX = 84)
    // 48 01 C8          ADD RAX, RCX   (RAX = 42 + 84 = 126)
    // C3                RET
    uint8_t code[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,   // MOV EAX, 42
        0x48, 0x89, 0xC1,                // MOV RCX, RAX
        0x48, 0xC1, 0xE1, 0x01,          // SHL RCX, 1
        0x48, 0x01, 0xC8,                // ADD RAX, RCX
        0xC3                             // RET
    };
    memcpy(pe + 0x200, code, sizeof(code));

    FILE *f = fopen(path, "wb");
    fwrite(pe, 1, sizeof(pe), f);
    fclose(f);
}

int main(int argc, char *argv[]) {
    wg_log_init();

    printf("=== WineGlass End-to-End PE Execution Test ===\n\n");

    // Build a test PE
    const char *pe_path = "/tmp/wineglass_test.exe";
    build_test_pe(pe_path);
    WG_LOGI("E2E", "Built test PE at %s", pe_path);

    // Create and initialize engine
    WGEngine *engine = wg_engine_create();
    if (!wg_engine_init(engine)) {
        WG_LOGE("E2E", "Engine init failed");
        return 1;
    }

    // Load the PE
    if (!wg_engine_load_pe(engine, pe_path)) {
        WG_LOGE("E2E", "PE load failed");
        return 1;
    }

    // Run it
    if (!wg_engine_run(engine)) {
        WG_LOGE("E2E", "Engine start failed");
        return 1;
    }

    // Execute until halt
    for (int i = 0; i < 100; i++) {
        wg_engine_tick(engine);
        WGEngineState state = wg_engine_get_state(engine);
        if (state != WG_ENGINE_RUNNING) {
            WG_LOGI("E2E", "Engine stopped with state: %d after tick %d", state, i + 1);
            break;
        }
    }

    WG_LOGI("E2E", "Test complete");
    printf("\n=== DONE ===\n");

    wg_engine_destroy(engine);
    return 0;
}
