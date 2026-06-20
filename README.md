# WineGlass

x86/x86-64 Windows translation layer for iOS. Runs Windows .exe files on iPhone through binary translation and Win32 API emulation.

## What It Does

- Loads and parses Windows PE/PE32+ executables
- Translates x86/x86-64 instructions to ARM64 via [blink](https://github.com/jart/blink) emulator
- Intercepts 190+ Win32 API calls (kernel32, user32, gdi32, shell32, advapi32, comctl32, ole32)
- Maps Windows file I/O to the iOS sandbox filesystem
- Renders Windows application windows via Metal compositor
- Handles stdcall/cdecl calling conventions with correct stack cleanup

## Architecture

```
Windows .exe (x86/x86-64)
       ↓
  PE Loader (parse sections, resolve imports)
       ↓
  Blink x86 Emulator (ARM64 interpreter)
       ↓
  Win32 API Thunks (HLT interception → native handlers)
       ↓
  iOS (Metal rendering, file I/O, UIKit)
```

## Building

### Prerequisites
- Xcode 15+ (tested with Xcode 27 beta)
- [XcodeGen](https://github.com/yonaskolb/XcodeGen): `brew install xcodegen`
- [blink](https://github.com/jart/blink) (built separately for iOS ARM64)

### Build blink for iOS
```bash
cd ~/Developer/blink
cp config.h.ios config.h
./configure CC=$(xcrun --sdk iphoneos -f clang) \
  AR=$(xcrun --sdk iphoneos -f ar) \
  CFLAGS="-g -O2 -arch arm64 -isysroot $(xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=17.0" \
  --disable-threads --disable-sockets --disable-jit
gmake -j$(sysctl -n hw.ncpu) o//blink/blink.a
cp o//blink/blink.a ~/Developer/WineGlass/Vendor/blink/lib/
```

Also compile the bridge:
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

### Build WineGlass
```bash
cd ~/Developer/WineGlass
xcodegen generate
open WineGlass.xcodeproj
# Set your development team, build and run on device
```

## Status

**Working on iPhone:**
- 64-bit and 32-bit x86 code execution (blink interpreter mode)
- PE loading with import table resolution (7+ DLLs, 190+ functions)
- Win32 API interception with correct stdcall stack cleanup
- Real file I/O mapped to iOS sandbox
- Window management and Metal compositor with text rendering
- Dialog pause/resume system
- Steam installer (SteamSetup.exe) executes ~10,000 ticks, creates windows, extracts data

## License

Apache 2.0
