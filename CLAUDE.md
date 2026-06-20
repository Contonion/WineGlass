# WineGlass — CLAUDE.md

## Project Overview

WineGlass is an x86/x86-64 Windows translation layer for iOS. It runs real Windows .exe files on iPhone by translating x86 instructions to ARM64 and intercepting Win32 API calls. Built from scratch starting June 19, 2026.

## Architecture

```
Windows .exe (PE32/PE32+)
    ↓ PE Loader (wg_pe_loader.c)
    ↓ Section mapping, import resolution
    ↓
Blink x86 Emulator (blink.a — interpreter mode, no JIT on iOS)
    ↓ Executes x86/x86-64 instructions on ARM64
    ↓ 32-bit PEs use SetMachineMode(LEGACY_32) on a LONG mode System
    ↓ (System stays LONG for page tables; Machine decodes 32-bit)
    ↓
Win32 API Thunks (HLT instructions at 0xC00000 range)
    ↓ Engine intercepts HLT, reads stack args, dispatches to handlers
    ↓ Stdcall stack cleanup: pop return_addr + (num_args * ptr_size)
    ↓
Native iOS (Metal rendering, file I/O, UIKit)
```

## Build System

- **Xcode project** generated via `xcodegen` from `project.yml`
- **Blink** is a separate build: clone github.com/jart/blink, configure with `--disable-jit --disable-threads --disable-sockets`, cross-compile for iOS arm64
- **blink.a** + **wg_blink_impl.o** go in `Vendor/blink/lib/`
- Blink headers in `Vendor/blink/include/blink/`
- Link flags: `-force_load` is NOT used (causes blinkenlights symbols); use direct .o + .a in OTHER_LDFLAGS
- `-Xlinker -undefined -Xlinker dynamic_lookup` for pthread_jit symbols

## Key Design Decisions

### Blink 32-bit Mode
- Cannot use `XED_MODE_LEGACY` for System — `ReserveVirtual` asserts `XED_MODE_LONG`
- Cannot call `SetMachineMode()` before loading — it changes System.mode too
- Solution: Create System in LONG mode, load all sections via ReserveVirtual, setup stack, THEN set `vm->m->mode = XED_MACHINE_MODE_LEGACY_32` directly (NOT via SetMachineMode which propagates to System)
- Fresh VM per PE load (`ensure_blink_vm` destroys old VM)

### Win32 API Interception
- Thunks are HLT (0xF4) instructions mapped at 0xC00000 (32-bit) or 0xDEAD0000 (64-bit)
- Each stub has `num_args` for stdcall stack cleanup
- `wsprintfW`/`wsprintfA` are cdecl (0 callee-cleaned args)
- `handle_blink_thunk()` reads 32-bit stack args, dispatches by function name
- Return value in EAX, stack cleaned: `RSP += ptr_size + (num_args * ptr_size)`

### NSIS Installer Data Decompression
- NSIS uses one continuous LZMA stream for the outer compression
- Blink's 32-bit compatibility mode produces corrupt LZMA output
- **Critical fix**: When NSIS creates its data .tmp file, intercept and decompress the entire outer LZMA stream natively using Apple's `compression_decode_buffer(COMPRESSION_LZMA)`
- The .tmp file must contain DECOMPRESSED outer-stream data (not raw compressed bytes from the .exe)
- Individual file blocks in the .tmp may have inner compression with their own headers
- `wg_nsis_extract.c` handles both outer stream decompression and individual file extraction

### File I/O
- Windows paths mapped to iOS sandbox: `C:\Temp\` → `{Documents}/`, `C:\a.exe` → actual .exe path
- Backslashes converted to forward slashes via `fix_separators()`
- `CreateFileW` respects GENERIC_WRITE flag for ALL creation dispositions
- Auto-creates parent directories for CREATE_ALWAYS/OPEN_ALWAYS
- `GetTempFileNameW` creates the actual file on disk (Windows behavior NSIS depends on)
- Null handles (`fp == NULL`) silently discard writes, return zeros on read

### Window Management & Rendering
- `WGWindowManager` tracks HWNDs, positions, sizes, titles, visibility
- `WGCompositor` renders windows via Metal with colored quads + Core Text title rendering
- `DialogBoxParamW` calls the NSIS dialog proc with WM_INITDIALOG (0x0110) so NSIS creates UI controls
- Engine pauses on `PeekMessageW` after dialog init so user can see windows
- Scene lifecycle uses `UIScene` (required by iOS 27 SDK)

### Blink Integration
- `wg_blink_impl.c` compiled separately with blink's headers (they shadow system headers)
- `wg_blink_bridge.c` calls through via extern declarations (no blink headers in Xcode build)
- `wg_blink_stubs.c` overrides `Abort()` and `TerminateSignal()` for library mode
- `Abort()` uses `siglongjmp` to recovery point instead of calling `abort()`
- `TerminateSignal()` longjmps via `wg_blink_set_onhalt()`
- JIT disabled on iOS (`DISABLE_JIT` in config.h.ios) — no entitlement available
- `FLAG_nolinear = true` required for embedded use (can't control host address space)
- `s->real` must be allocated even in LONG mode (page table backing store)
- `s->cr3 = AllocatePageTable(s)` required before any ReserveVirtual call
- Warm-up NOP+RET absorbs first-run initialization abort

## Source File Guide

### Sources/Core/
- `wg_engine.c` (1043 lines) — Main orchestrator. PE loading, blink VM lifecycle, Win32 thunk dispatch, NSIS data patching. Contains ALL explicit Win32 API handlers.
- `wg_blink_bridge.c` — Bridge between WineGlass and blink. Extern declarations for WGBlinkVM_* symbols. Abort recovery via sigsetjmp.
- `wg_blink_stubs.c` — Overrides for blink's Abort() and TerminateSignal(). WriteErrorString capture.
- `wg_selftest.c` — 66 tests: decoder, interpreter, PE parser, blink execution, PE with imports
- `wg_log.c` — Logging with callbacks, ring buffer, log levels

### Sources/PE/
- `wg_pe_loader.c` — Full PE32/PE32+ parser. DOS header, COFF, optional header, sections, import directory with ILT/IAT resolution.

### Sources/CPU/
- `wg_x86_decode.c` — x86-64 instruction decoder (~80 opcode families). REX prefixes, ModR/M, SIB.
- `wg_x86_interp.c` — Builtin interpreter (fallback). MOV, ADD, SUB, AND, OR, XOR, CMP, JCC, CALL, RET, etc.
- `wg_x86_state.c` — CPU state: 16 GPRs, RFLAGS, XMM, FPU. Flag computation for add/sub/logic.

### Sources/Win32/
- `wg_dll_mapper.c` — Win32 stub registry. 190+ functions across 7 DLLs. Each entry has name, thunk address, handler function, num_args.
- `wg_win32_windows.c` — Window manager. HWND table, create/show/destroy/set_text.
- `wg_win32_files.c` — File handle table backed by fopen/fread/fwrite. Path mapping, null handles, NSIS data prepopulation.
- `wg_nsis_extract.c` — Native NSIS file extraction. Outer LZMA stream decompression via Apple Compression framework. Individual file block extraction.

### Sources/Graphics/
- `WGCompositor.m` — Metal compositor. Renders window rectangles with title bars, close buttons, shadows. Text via UIGraphicsImageRenderer → Metal texture.

### Sources/App/
- `WGSceneDelegate.m` — UIScene lifecycle, Metal setup, render loop, file picker, engine tick, dialog pause/resume
- `WGMetalView.m` — CAMetalLayer-backed UIView
- `WGConsoleOverlay.m` — On-screen debug console with color-coded log

### Sources/Memory/
- `wg_memory.c` — Virtual memory for builtin interpreter (not used with blink)

### Vendor/blink/
- `wg_blink_impl.c` — Bridge implementation compiled with blink headers. VM create/destroy, load code, step/run, register/memory access. Must be compiled separately due to header shadowing.
- `lib/blink.a` — Prebuilt blink static library for iOS arm64 (not in git)
- `lib/wg_blink_impl.o` — Prebuilt bridge object (not in git)
- `include/` — Blink headers (83 files)

## Known Issues

1. **CALL/RET test failure** (2 tests): TerminateSignal longjmp during RET-to-address-0 doesn't preserve register state for the instructions between CALL return and RET. Cosmetic — real programs use ExitProcess.

2. **RESOLVED 2026-06-20 — blink decodes LZMA correctly.** The "interpreter
   desync" theory below was DISPROVEN: CPU and memory conformance probes
   (Tests/cpu_probe.c → 0x1FFFF all-pass; Tests/mem_probe.c → 0x800007FF
   all-pass, including a 12MB allocation) showed blink's 32-bit interpreter is
   accurate for every instruction class LZMA uses, AND for large allocations.
   With our native-extraction interference removed and the GlobalAlloc
   threshold raised so the 8MB LZMA dictionary allocates, SteamSetup's solid
   stream decompresses correctly (full 32768-byte chunks, no corrupt sizes).
   The real cause of every "Error decompressing data" was OUR own band-aids
   (null handles discarding blink's correct output), not the emulator. The
   installer now extracts data and reaches plug-in directory setup. Next
   blockers are Win32 completeness (plug-in dir init, then the real UI).
   The probes (WGProbe.exe/WGMem.exe) remain bundled, loadable via picker.

   [HISTORICAL / WRONG] LZMA decompression desync — THE core blocker:
   - SteamSetup.exe uses a SOLID raw-LZMA stream (props `5d`, 8MB dict). The
     stream is 100% standard: Python's `lzma.FORMAT_RAW` decodes it cleanly to
     7,931,223 bytes (203,614 header + 7,727,609 file data).
   - blink decodes the EARLY part correctly (the dialog, control IDs, strings,
     fonts all come from the decompressed header and render fine) then desyncs
     DETERMINISTICALLY — same wrong value (`GlobalAlloc(2174029109)`) every run.
   - It is NOT JIT: blink.a was built with DISABLE_JIT (exports
     `_JitlessDispatch`, no Jitter symbols). It runs the INTERPRETER. So the
     desync is an interpreter accuracy bug on some instruction in LZMA's hot
     loop, data-dependent, only hit by heavy decode work.
   - Apple's `COMPRESSION_LZMA` only reads the .xz/.lzma CONTAINER, NOT a raw
     NSIS stream — native bypass via libcompression is impossible. Would need
     to bundle LzmaDec.c (LZMA SDK, public domain) for native decode.
   - Output-redirection CANNOT fix it: NSIS reads its control values (block
     sizes, file table) directly from the decoder's output, so a desynced
     decoder makes NSIS take wrong branches regardless of what's written to
     disk. The only real fixes are (a) fix blink's interpreter, or (b) fully
     reimplement NSIS extraction natively (and skip running its x86 extractor).
   - The previous "native extraction" interception was REMOVED — it returned
     null handles that discarded blink's (correct, early) output and made
     things worse.

3. **VALIDATED 2026-06-20**: The window + GDI + Metal compositor + message-loop
   pipeline works end-to-end on device. `Tests/gdi_test.c` (a controlled
   straight-line 32-bit PE built with mingw-w64 i686) renders a window with
   FillRect/TextOutW/LineTo content on the iPhone. This proves blink's 32-bit
   interpreter is correct for straight-line code; only the heavy LZMA loop
   desyncs. Build it with: `i686-w64-mingw32-gcc -O1 -ffreestanding -nostdlib
   -fno-builtin -e _start_ -Wl,--subsystem,windows -o WGTest.exe gdi_test.c
   -lkernel32 -luser32 -lgdi32`. It is bundled in the app (Resources/) and
   loaded preferentially by tryLoadBundledPE during this validation phase.

3. **System.dll loading**: NSIS extracts System.dll successfully (23KB) but can't LoadLibrary it (we return a fake module handle). System::Call functionality is stubbed.

4. **First-run warm-up**: First x86 execution on a new blink VM triggers an abort (page fault during JIT init even with JIT disabled). Absorbed by a NOP+RET warm-up before real execution.

5. **GlobalAlloc heap exhaustion**: Static heap pointer at 0x10000000 never resets within a session. Large allocations (>16MB) are failed to prevent corrupt-size crashes.

## Testing

```bash
# Command-line tests (macOS)
cd ~/Developer/blink && ./configure --disable-threads --disable-sockets
gmake -j$(sysctl -n hw.ncpu) o//blink/blink.a
# Compile bridge impl for macOS...
cd ~/Developer/WineGlass && clang ... -o Tests/test_runner && ./Tests/test_runner

# iOS build
xcodegen generate
# Open WineGlass.xcodeproj, set team, build for device
```

## Steam Installer Execution Trace

SteamSetup.exe (32-bit NSIS installer, 2.3MB) executes ~10,000 ticks:
1. SetErrorMode, GetVersion — init
2. GetProcAddress(SetDefaultDllDirectories) — security
3. LoadLibraryExW × 9 — system DLL loading
4. GetProcAddress(GetFileVersionInfoW, SHGetFolderPathW) — version/shell
5. OleInitialize, SHGetFileInfoW — COM init
6. CreateFileW('C:\a.exe') → opens real .exe on iOS filesystem
7. GetFileSize → 2,380,800 bytes
8. ReadFile × hundreds — reads installer data (512-byte blocks, then 32KB chunks)
9. WriteFile × many — decompresses and writes data to .tmp
10. CreateDialogParamW × 7, ShowWindow × 7 — creates installer UI
11. GlobalAlloc (200KB + 52KB + 8MB) — decompression buffers
12. GetUserDefaultUILanguage — language detection
13. SetWindowTextW — sets "Steam Setup" title
14. RegOpenKeyExW, RegQueryValueExW — registry checks
15. CreateDirectoryW — creates plugin directory
16. System.dll extracted (23,400 bytes) ← LZMA decompression works for this file
17. DialogBoxParamW → calls dialog proc with WM_INITDIALOG
18. GetDlgItem, SetDlgItemTextW, CreateFontIndirectW — populates dialog controls
19. modern-header.bmp extraction (fails due to LZMA state corruption)
20. "Steam Setup" window rendered via Metal compositor on iPhone screen

## Environment

- macOS (Tahoe/Sequoia) with Xcode 27 beta
- iOS 27 on iPhone 15 Pro (A17 Pro, Apple GPU family 9)
- Blink from github.com/jart/blink (ISC license)
- Apple Compression framework for native LZMA
