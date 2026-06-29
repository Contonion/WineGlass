#!/bin/bash
# build_mac_jit.sh — Same as build_mac.sh but builds blink with JIT ENABLED
# (x86->ARM translation, like a mini-Rosetta). macOS allows JIT; iOS does not.
# Purpose: a CORRECT-execution reference to diff against the interpreter build,
# so we can pin the exact x86 instruction blink's interpreter miscomputes.
#
#   Tests/build_mac_jit.sh && /tmp/wineglass_mac_jit/wineglass_run ~/Downloads/Steam.exe 25
set -e
WG="$(cd "$(dirname "$0")/.." && pwd)"
BLINK="${BLINK_SRC:-$HOME/Developer/blink}"
BUILD="${BUILD_DIR:-/tmp/wineglass_mac_jit}"
mkdir -p "$BUILD"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
CC="clang -arch arm64 -isysroot $SDK -O1 -g -Wno-everything"

# 1. blink.a for macOS arm64 WITH JIT (config.h.jit = config.h sans DISABLE_JIT)
if [ ! -f "$BUILD/blink_macos_jit.a" ] || [ "$1" = "rebuild" ]; then
  echo "building blink_macos_jit.a (JIT enabled) ..."
  ( cd "$BLINK"
    cp config.h config.h.realbak
    sed 's|^#define DISABLE_JIT.*|/* DISABLE_JIT off: macOS JIT reference */|' config.h.realbak > config.h
    grep -q 'DISABLE_JIT off' config.h || { echo "config patch failed"; exit 1; }
    rm -rf "$BUILD/obj"; mkdir -p "$BUILD/obj"
    for o in $(ar t "$WG/Vendor/blink/lib/blink.a.bak" | grep -v SYMDEF); do
      $CC -I. -c "blink/${o%.o}.c" -o "$BUILD/obj/$o" 2>>"$BUILD/cc.log" || echo "FAIL ${o}" >>"$BUILD/cc.log"
    done
    cp config.h.realbak config.h   # restore interpreter config immediately
    ar rcs "$BUILD/blink_macos_jit.a" "$BUILD/obj"/*.o; ranlib "$BUILD/blink_macos_jit.a" )
fi

# 2. bridge impl (needs blink headers)
$CC -I"$WG/Vendor/blink/include" -c "$WG/Vendor/blink/wg_blink_impl.c" -o "$BUILD/wg_blink_impl_macos.o"

# 3. engine + runner -> wineglass_run
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
  "$BUILD/wg_blink_impl_macos.o" "$BUILD/blink_macos_jit.a" \
  -framework Security -framework CoreFoundation -framework CoreGraphics -framework CoreText \
  -o "$BUILD/wineglass_run"
echo "built (JIT): $BUILD/wineglass_run"
