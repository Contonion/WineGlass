#!/bin/bash
# build_mac.sh — Build a headless macOS runner for the WineGlass engine so a
# Windows .exe (e.g. Steam) can be run + diagnosed on the Mac directly, with no
# iOS device round-trip. Uses the SAME blink config as iOS (interpreter, no JIT,
# config.h.ios) so behavior matches the device.
#
#   Tests/build_mac.sh && <build>/wineglass_run ~/Downloads/Steam.exe 25
#
# Outputs go to $BUILD (scratch); blink.a/impl.o are gitignored like on iOS.
set -e
WG="$(cd "$(dirname "$0")/.." && pwd)"
BLINK="${BLINK_SRC:-$HOME/Developer/blink}"
BUILD="${BUILD_DIR:-/tmp/wineglass_mac}"
mkdir -p "$BUILD"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
CC="clang -arch arm64 -isysroot $SDK -O1 -g -Wno-everything"

# 1. blink.a for macOS arm64 (only if missing — slow). Uses blink's current
#    config.h (copy config.h.ios over it first if you changed flags).
if [ ! -f "$BUILD/blink_macos.a" ]; then
  echo "building blink_macos.a ..."
  ( cd "$BLINK"
    [ -f config.h ] || cp config.h.ios config.h
    rm -rf "$BUILD/obj"; mkdir -p "$BUILD/obj"
    for o in $(ar t "$WG/Vendor/blink/lib/blink.a.bak" | grep -v SYMDEF); do
      $CC -I. -c "blink/${o%.o}.c" -o "$BUILD/obj/$o"
    done
    ar rcs "$BUILD/blink_macos.a" "$BUILD/obj"/*.o; ranlib "$BUILD/blink_macos.a" )
fi

# 2. bridge impl (needs blink headers)
$CC -I"$WG/Vendor/blink/include" -c "$WG/Vendor/blink/wg_blink_impl.c" -o "$BUILD/wg_blink_impl_macos.o"

# 3. engine core + LZMA + runner -> wineglass_run
$CC \
  -I"$WG/Sources/Core" -I"$WG/Sources/CPU" -I"$WG/Sources/PE" -I"$WG/Sources/Memory" \
  -I"$WG/Sources/Win32" -I"$WG/Sources/Graphics" -I"$WG/Sources/LZMA" \
  "$WG/Sources/Core/wg_engine.c" "$WG/Sources/Core/wg_blink_bridge.c" \
  "$WG/Sources/Core/wg_blink_stubs.c" "$WG/Sources/Core/wg_log.c" \
  "$WG/Sources/CPU/wg_x86_decode.c" "$WG/Sources/CPU/wg_x86_interp.c" "$WG/Sources/CPU/wg_x86_state.c" \
  "$WG/Sources/PE/wg_pe_loader.c" "$WG/Sources/Memory/wg_memory.c" \
  "$WG"/Sources/Win32/wg_dll_mapper.c "$WG"/Sources/Win32/wg_nsis_extract.c \
  "$WG"/Sources/Win32/wg_schannel.c "$WG"/Sources/Win32/wg_threading.c \
  "$WG"/Sources/Win32/wg_win32_bitmap.c "$WG"/Sources/Win32/wg_win32_files.c \
  "$WG"/Sources/Win32/wg_win32_gdi.c "$WG"/Sources/Win32/wg_win32_windows.c \
  "$WG"/Sources/Win32/wg_winhttp.c "$WG"/Sources/Win32/wg_winsock.c \
  "$WG/Sources/LZMA/LzmaDec.c" "$WG/Tests/run_exe.c" \
  "$WG/Tests/wg_native_download_mac.m" \
  "$BUILD/wg_blink_impl_macos.o" "$BUILD/blink_macos.a" \
  -framework Security -framework CoreFoundation -framework Foundation \
  -framework CoreGraphics -framework CoreText \
  -o "$BUILD/wineglass_run"
echo "built: $BUILD/wineglass_run"
