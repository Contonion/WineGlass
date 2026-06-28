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
- **IMPORTANT**: Run `xcodegen generate` after adding any new source files — missing files cause null-symbol crashes masked by `-undefined dynamic_lookup`
- **Blink** is a separate build: clone github.com/jart/blink, configure with `--disable-jit --disable-threads --disable-sockets`, cross-compile for iOS arm64
- **blink.a** + **wg_blink_impl.o** go in `Vendor/blink/lib/`
- Blink headers in `Vendor/blink/include/blink/`
- Link flags: `-force_load` is NOT used (causes blinkenlights symbols); use direct .o + .a in OTHER_LDFLAGS
- `-Xlinker -undefined -Xlinker dynamic_lookup` for pthread_jit symbols
- **Security.framework** linked for SecureTransport (SSL/TLS)

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
- **Auto-stubs** for unknown functions get `num_args=0` — correct for cdecl but causes stack leak for stdcall functions with args (each call leaks 4*N bytes). Register critical functions with correct arg counts.

### SSL/TLS Networking Stack (added 2026-06-23)
Three-layer approach for HTTPS support:

1. **WinHTTP** (`wg_winhttp.c`) — High-level HTTP client backed by raw sockets + Apple SecureTransport for TLS. Handles WinHttpOpen/Connect/OpenRequest/SendRequest/ReceiveResponse/ReadData. Follows redirects (301/302/303/307/308). Used when Steam calls WinHTTP directly.

2. **Schannel/SSPI** (`wg_schannel.c`) — Windows SSPI interface for TLS, backed by SecureTransport with buffer-based IO. Handles AcquireCredentialsHandleW, InitializeSecurityContextW (incremental TLS handshake via buffered read/write callbacks), EncryptMessage, DecryptMessage. Used when Steam does raw socket + Schannel TLS.

3. **Winsock extensions** — `ConnectEx` (async connect via `WSAIoctl SIO_GET_EXTENSION_FUNCTION_POINTER`), `DisconnectEx`, `AcceptEx`. Steam uses `ConnectEx` instead of plain `connect()` for async TCP connections.

**SecureTransport** is deprecated (iOS 13+) but still functional. Pragmas suppress warnings. The C API is the only TLS option from plain C code without Objective-C bridging.

### Steam Bootstrapper Requirements (discovered 2026-06-23)
Steam's bootstrapper (steam.exe) performs these checks before attempting downloads:
1. **Directory writable** — Opens `C:\package\.writable`, calls `GetFileType`. Must return `FILE_TYPE_DISK` (1), not `FILE_TYPE_UNKNOWN` (0).
2. **Network adapter present** — Calls `GetAdaptersAddresses` or `GetAdaptersInfo` from `IPHLPAPI.DLL`. Must return at least one adapter with OperStatus=UP.
3. **Disk space** — Calls `GetDiskFreeSpaceExW`. Must return non-zero free space.
4. **Network connectivity** — May call `InternetGetConnectedState` from `wininet.dll`.

If ANY check fails, Steam logs the error to `C:\package\bootstrap_log.txt` (handle 0x112) and exits with code -1 (~61196 ticks).

Steam downloads from: `https://cdn.steamstatic.com/client/steam_client_win32`

### CRT Initialization Requirements
Steam's MSVC CRT calls many functions during initialization that MUST write to output buffers (not just return success):
- **`GetStringTypeW`** — Must write character type classification (CT_CTYPE1) to output WORD array. Crash if output is garbage.
- **`LCMapStringW/Ex`** — Must copy/transform string to output buffer and return length.
- **`GetCPInfo`** — Must write CPINFO struct (MaxCharSize, DefaultChar, LeadByte).
- **`GetStartupInfoW`** — Must write zeroed STARTUPINFOW (68 bytes) with cb field set.
- **`InitOnceBeginInitialize`** — R1S stub is OK (fPending stays as stack value, happens to work). DO NOT add engine handler that writes fPending=TRUE — it changes CRT init path and causes crashes.
- **`InitializeCriticalSectionEx`** — R1S stub is OK. DO NOT add engine handler that writes to CRITICAL_SECTION — it corrupts adjacent data.
- **`LoadLibraryExW('')`** — Empty string must return main module handle (image_base), NOT a fake DLL handle.

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
- **WriteFile** succeeds silently for unknown handles (stdout 0xF1, stderr 0xF2, pipes 0x7301) to prevent thread crashes
- **GetFileType** returns `FILE_TYPE_DISK` (1) for handles in range 0x100-0x1FF

### Bottle System
- Persistent `drive_c` prefix at `{Documents}/Bottle/drive_c/`
- All `C:\` paths map under the bottle
- Steam installs go there, not scattered temp

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
- `wg_engine.c` — Main orchestrator. PE loading, blink VM lifecycle, Win32 thunk dispatch, NSIS data patching. Contains ALL explicit Win32 API handlers including networking dispatch (WS2_32, WinHTTP, Schannel, WinINet, IPHLPAPI).
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
- `wg_dll_mapper.c` — Win32 stub registry. 600+ functions across 15+ DLLs. Each entry has name, thunk address, handler function, num_args.
- `wg_winsock.c` — Winsock (WS2_32/WSOCK32) implementation. Real BSD sockets mapped via handle table. Supports socket/connect/send/recv/select/getaddrinfo/ConnectEx. Handle base 0x1000, max 128 sockets.
- `wg_winhttp.c` — WinHTTP API implementation. HTTP client with TLS via SecureTransport. Handle table at base 0x3000, max 16 slots. Supports WinHttpOpen through WinHttpReadData + URL cracking + redirects.
- `wg_schannel.c` — Schannel/SSPI implementation. TLS via SecureTransport with buffer-based IO callbacks bridging SSPI's incremental handshake model. Supports AcquireCredentialsHandle, InitializeSecurityContext, EncryptMessage, DecryptMessage.
- `wg_win32_windows.c` — Window manager. HWND table, create/show/destroy/set_text.
- `wg_win32_files.c` — File handle table backed by fopen/fread/fwrite. Path mapping, null handles, NSIS data prepopulation.
- `wg_win32_gdi.c` — GDI stubs.
- `wg_win32_bitmap.c` — Bitmap handling.
- `wg_nsis_extract.c` — Native NSIS file extraction. Outer LZMA stream decompression via Apple Compression framework.
- `wg_threading.c` — Thread scheduler. Cooperative multithreading with per-thread TEB, stack, register save/restore. Max 8 threads.

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

## DLL Stub Registry

### Registered DLLs (wg_dll_mapper.c)
- KERNEL32.dll (~200 functions)
- USER32.dll (~70 functions)
- GDI32.dll (~20 functions)
- ADVAPI32.dll (~15 functions)
- SHELL32.dll, ole32.dll, OLEAUT32.dll, COMCTL32.dll
- WS2_32.dll / WSOCK32.dll (~30 functions + ConnectEx/DisconnectEx/AcceptEx)
- winhttp.dll (18 functions)
- wininet.dll (26 functions)
- crypt32.dll (14 functions)
- secur32.dll / sspicli.dll / schannel.dll (SSPI functions)
- bcrypt.dll (BCryptGenRandom with real arc4random)
- IPHLPAPI.DLL (GetAdaptersAddresses/Info, GetNetworkParams, GetBestInterface)
- vcruntime140.dll, ucrtbase.dll, msvcp140.dll (VC++ runtime stubs)
- VERSION.dll, PSAPI.DLL

## Known Issues

1. **CALL/RET test failure** (2 tests): TerminateSignal longjmp during RET-to-address-0 doesn't preserve register state for the instructions between CALL return and RET. Cosmetic — real programs use ExitProcess.

2. **Steam networking in progress**: Steam reaches "Checking for available update" and creates a download thread. WSAStartup, socket creation, and ConnectEx resolution work. Next: verify ConnectEx TCP connections complete and Schannel TLS handshake succeeds for `cdn.steamstatic.com:443`.

3. **System.dll loading**: NSIS extracts System.dll successfully (23KB) but can't LoadLibrary it (we return a fake module handle). System::Call functionality is stubbed.

4. **First-run warm-up**: First x86 execution on a new blink VM triggers an abort (page fault during JIT init even with JIT disabled). Absorbed by a NOP+RET warm-up before real execution.

5. **GlobalAlloc heap exhaustion**: Static heap pointer at 0x10000000 never resets within a session. Large allocations (>16MB) are failed to prevent corrupt-size crashes.

6. **CRT init sensitivity**: Adding engine handlers for InitOnceBeginInitialize, InitializeCriticalSectionEx, or EnterCriticalSection causes crashes by changing CRT initialization paths. The R1S/RS stub defaults work. Only add engine handlers for functions that MUST write output buffers (GetStringTypeW, GetCPInfo, LCMapStringW, GetStartupInfoW).

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

## Steam Bootstrapper Execution Trace

Steam.exe (32-bit PE, ~4MB, 5 sections) executes as follows:
1. CRT init: LoadLibraryExW(api-ms-win-core-*), GetProcAddress for InitializeCriticalSectionEx/FlsAlloc/FlsSetValue
2. CRT locale: GetACP→1252, GetCPInfo, GetStringTypeW, LCMapStringEx, MultiByteToWideChar
3. Startup: GetCommandLineA/W, GetStartupInfoW, GetStdHandle×3
4. UI setup: CreateWindowExW, SetWindowTextW("Updating Steam..."), SetDlgItemTextW("Checking for available update...")
5. Pre-flight checks:
   - CreateFileW("C:\package\.writable") + GetFileType → must return FILE_TYPE_DISK
   - GetDiskFreeSpaceExW → must return non-zero space
   - IPHLPAPI GetAdaptersAddresses → must return active adapter
6. Download thread: CreateThread → WSAStartup → socket → WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER/ConnectEx)
7. Manifest download: ConnectEx to cdn.steamstatic.com:443 → Schannel TLS → HTTP GET /client/steam_client_win32
8. Thread 1 polls via Sleep loop waiting for download completion

## Environment

- macOS (Tahoe/Sequoia) with Xcode 27 beta
- iOS 27 on iPhone (A17 Pro, Apple GPU family 9)
- Blink from github.com/jart/blink (ISC license)
- Apple Compression framework for native LZMA
- Apple Security framework for SecureTransport TLS
