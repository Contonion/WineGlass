# WineGlass

x86/x86-64 Windows translation layer for iOS. Runs Windows `.exe` files on iPhone through binary translation and Win32 API emulation.

## What It Does

- Loads and parses Windows PE/PE32+ executables
- Translates x86/x86-64 instructions to ARM64 via the [blink](https://github.com/jart/blink) emulator (JIT on device)
- Intercepts 600+ Win32 API calls across 15+ DLLs (kernel32, user32, gdi32, shell32, advapi32, comctl32, ole32, ws2_32, winhttp, wininet, crypt32, secur32/schannel, bcrypt, iphlpapi, the VC++/UCRT runtime, …)
- Maps Windows file I/O to the iOS sandbox filesystem (persistent `C:\` bottle)
- HTTPS/TLS stack: WinHTTP, Schannel/SSPI and Winsock (incl. `ConnectEx`) backed by real sockets + Apple SecureTransport
- Decodes NSIS installers' solid-LZMA data natively and serves it to the guest
- Renders Win32 **dialogs** by parsing their resource templates (`RT_DIALOG`) into a Metal-composited framebuffer, with modal button routing (`WM_COMMAND`)
- **D3D11/DXGI → Metal** backend (`wg_d3d11.c` + `WGMetalBackend.m`): device/swapchain creation, COM vtables, and a DXBC→MSL shader path (`wg_dxbc.c`) — enough to bring a Direct3D 11 renderer up on Metal
- **Real multithreading**: guest threads run on real pthreads serialized by a Global Interpreter Lock (directed hand-off), with per-thread TEB/FLS/TLS; a cooperative single-thread scheduler is also available
- Handles stdcall/cdecl calling conventions with correct stack cleanup

## Architecture

```
Windows .exe (x86/x86-64, PE32/PE32+)
       ↓
  PE Loader (parse sections, resolve imports)
       ↓
  Blink x86 Emulator (ARM64, JIT + software-MMU / native-linear "Path B")
       ↓
  Win32 API Thunks (HLT interception → native handlers)
       ↓
  iOS (Metal rendering incl. D3D11→Metal, file I/O, UIKit)
```

## Building

### Prerequisites
- Xcode 15+ (developed against Xcode 27 beta)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- [blink](https://github.com/jart/blink) (built separately for iOS ARM64)

### Build blink for iOS
```bash
cd ~/Developer/blink
cp config.h.ios config.h
./configure CC=$(xcrun --sdk iphoneos -f clang) \
  AR=$(xcrun --sdk iphoneos -f ar) \
  CFLAGS="-g -O2 -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=17.0" \
  --disable-threads --disable-sockets
gmake -j$(sysctl -n hw.ncpu) o//blink/blink.a
cp o//blink/blink.a ~/Developer/WineGlass/Vendor/blink/lib/
```

Also compile the bridge (`wg_blink_impl.c` — needs blink's headers, so it is built separately from the Xcode target):
```bash
$(xcrun --sdk iphoneos -f clang) -c -std=c11 -g -O2 -arch arm64 \
  -isysroot $(xcrun --sdk iphoneos --show-sdk-path) \
  -miphoneos-version-min=17.0 \
  -D_FILE_OFFSET_BITS=64 -D_DARWIN_C_SOURCE -DTARGET_OS_IPHONE=1 \
  -isystem $(xcrun --sdk iphoneos --show-sdk-path)/usr/include \
  -I. -include config.h \
  ~/Developer/WineGlass/Vendor/blink/wg_blink_impl.c \
  -o ~/Developer/WineGlass/Vendor/blink/lib/wg_blink_impl.o
```

### Build WineGlass (device)
```bash
cd ~/Developer/WineGlass
xcodegen generate      # re-run after adding any source file
open WineGlass.xcodeproj
# Set your development team, build and run on device
```

### Desktop harness (macOS)
`Tests/build_mac_window.sh` builds a windowed macOS binary (`wineglass_window`) that runs the **same** blink interpreter as the device and presents the guest's D3D11→Metal output to a real `NSWindow`, so behaviour and speed match the phone. This is the main debugging vehicle:
```bash
WG_BUILD_PATHB=1 Tests/build_mac_window.sh
/tmp/wineglass_mac/wineglass_window "<path-to>/Some.exe"
```
The engine is heavily instrumentable via `WG_*` environment knobs (slice tuning, GIL pinning, scheduling, and diagnostics such as `WG_RIPSAMPLE`, `WG_STALLPROBE`, `WG_SETEVLOG`, `WG_TASKPROBE`).

> **Note:** game/asset trees are never committed. `GameData/` and `Tests/Bottle/` are git-ignored; the prebuilt `blink.a`/`wg_blink_impl.o` are too large for git and are built as above.

## Status

**Working on iPhone:**
- 64-bit and 32-bit x86 code execution (blink, JIT on device)
- PE loading with import table resolution (15+ DLLs, 600+ functions)
- Win32 API interception with correct stdcall stack cleanup
- Real file I/O mapped to an iOS-sandbox `C:\` bottle
- Window management + Metal compositor; dialog control rendering from templates
- Modal dialogs with clickable Next / Cancel routed as `WM_COMMAND`
- Networking/TLS: WinHTTP, Schannel/SSPI, Winsock + `ConnectEx` over SecureTransport
- Full-speed emulation decoupled from the 60 Hz UI; real-threads GIL scheduler

**Steam installer (SteamSetup.exe):** extracts its entire payload and brings up the wizard — the Steam logo header and Back/Install/Cancel buttons render, and Next/Cancel drive the wizard forward.

**UE4 game (Unreal Engine 4.24, 64-bit):** the current frontier. The engine boots through CRT/locale init, the RHI comes up (`CreateDXGIFactory1` → `D3D11CreateDevice`), the window is shown, and — in real-threads mode — reaches **`create_swapchain` ("Present is next") corruption-free with a live, advancing asset drain**. Two multithreading correctness bugs were fixed to get here (x64 thread-proc argument in `RCX`, and x64 entry-stack alignment), along with a construction-order data race in the engine's UObject registration that only manifests under true parallelism (see below). The boot has not yet reached a first rendered frame; it currently stalls after the swapchain in a UE4 name-lookup hot path and the task-graph work-dispatch handshake — both under active investigation.

### Notable findings along the way

- **Construction-order race:** UE4's object registration publishes an object pointer *before* linking its fields (a recursion-safety pattern that is only safe single-threaded). Running registration across real pthreads let a worker observe the half-built object. An opt-in gate (`WG_BLOCK_WORKERS`) that serializes early registration removes the corruption and lets real-threads mode reach the swapchain cleanly. A general-purpose **inline guest-code hook** (`WG_CTOR_HOOK`) was also built for per-call serialization (arms a `HLT`, emulates the displaced instruction, and re-arms so it keeps trapping under the JIT).
- **File-I/O truncation:** `ReadFile` capped every read at 1 MB, silently truncating a 5.7 MB global-shader cache and triggering a "missing shader" fatal error. Raising the cap fixed it and un-truncated all large asset reads.
- **NSIS "Corrupted installer?"** was **not** an emulator bug — reproduced byte-for-byte under both blink and an independent Unicorn (QEMU TCG) backend. A `lstrcpynW` stub wrote the full `maxlen` buffer, overflowing the destination and corrupting NSIS's in-guest LZMA decoder. The macOS harness (real engine as a CLI) made it debuggable off-device.

## License

Apache 2.0
