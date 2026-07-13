#!/bin/bash
# build_mac_window.sh — Like build_mac.sh, but produces a WINDOWED macOS app
# (wineglass_window) that presents the guest's D3D11->Metal output to a real
# NSWindow/CAMetalLayer, so you can SEE what the game renders. Same blink
# interpreter as iOS (Apple Silicon), so behaviour/speed match the device.
#
#   Tests/build_mac_window.sh && /tmp/wineglass_mac/wineglass_window "<GameData>/…/Visage.exe"
#
# WGMetalBackend.m's strong wg_gpu_* symbols override the weak headless stubs in
# wg_d3d11.c, so this build renders for real.
set -e
WG="$(cd "$(dirname "$0")/.." && pwd)"
BLINK="${BLINK_SRC:-$HOME/Developer/blink}"
BUILD="${BUILD_DIR:-/tmp/wineglass_mac}"
mkdir -p "$BUILD"
SDK="$(xcrun --sdk macosx --show-sdk-path)"
CC="clang -arch arm64 -isysroot $SDK -O2 -g -Wno-everything"
ARCC="$CC -fobjc-arc"
BLINKCC="clang -arch arm64 -isysroot $SDK -O3 -Wno-everything"

# WG_BUILD_PATHB=1 => Path B (native linear memory): -DWG_PATHB leaves
# WG_NOLINEAR_JIT undefined (kSkew nonzero, JIT emits host=kSkew+va) and enables
# the big pre-mapped guest region. Separate archive so the proven Path A stays cached.
PATHB_DEF=""; ARCH_TAG="macos"
if [ -n "$WG_BUILD_PATHB" ]; then PATHB_DEF="-DWG_PATHB"; ARCH_TAG="macos_pathb"; echo "[build] PATH B (native linear memory)"; fi
BLINKA="$BUILD/blink_${ARCH_TAG}.a"; BLINKOBJ="$BUILD/obj_${ARCH_TAG}"

# 1. blink.a for macOS arm64 (shared with build_mac.sh; rebuild if config changed)
if [ ! -f "$BLINK/config.h" ] || ! cmp -s "$BLINK/config.h.ios" "$BLINK/config.h"; then
  cp "$BLINK/config.h.ios" "$BLINK/config.h"
  rm -f "$BUILD/blink_macos.a" "$BUILD/blink_macos_pathb.a"
fi
if [ ! -f "$BLINKA" ]; then
  echo "building $(basename "$BLINKA") ..."
  ( cd "$BLINK"
    rm -rf "$BLINKOBJ"; mkdir -p "$BLINKOBJ"
    for o in $(ar t "$WG/Vendor/blink/lib/blink.a.bak" | grep -v SYMDEF); do
      $BLINKCC $PATHB_DEF -I. -c "blink/${o%.o}.c" -o "$BLINKOBJ/$o"
    done
    ar rcs "$BLINKA" "$BLINKOBJ"/*.o; ranlib "$BLINKA" )
fi

# 2. bridge impl (needs blink headers)
$CC $PATHB_DEF -I"$WG/Vendor/blink/include" -c "$WG/Vendor/blink/wg_blink_impl.c" -o "$BUILD/wg_blink_impl_macos.o"

# 3. ARC Objective-C: real Metal backend + windowed main
$ARCC -I"$WG/Sources/Core" -I"$WG/Sources/Graphics" -c "$WG/Sources/Graphics/WGMetalBackend.m" -o "$BUILD/WGMetalBackend.o"
$ARCC -I"$WG/Sources/Core" -c "$WG/Tests/mac_window_main.m" -o "$BUILD/mac_window_main.o"

# 4. engine core + LZMA + backend + window -> wineglass_window
$CC \
  -I"$WG/Sources/Core" -I"$WG/Sources/CPU" -I"$WG/Sources/PE" -I"$WG/Sources/Memory" \
  -I"$WG/Sources/Win32" -I"$WG/Sources/Graphics" -I"$WG/Sources/LZMA" \
  "$WG/Sources/Core/wg_engine.c" "$WG/Sources/Core/wg_blink_bridge.c" \
  "$WG/Sources/Core/wg_blink_stubs.c" "$WG/Sources/Core/wg_log.c" \
  "$WG/Sources/CPU/wg_x86_decode.c" "$WG/Sources/CPU/wg_x86_interp.c" "$WG/Sources/CPU/wg_x86_state.c" \
  "$WG/Sources/PE/wg_pe_loader.c" "$WG/Sources/Memory/wg_memory.c" \
  "$WG"/Sources/Win32/wg_dll_mapper.c "$WG"/Sources/Win32/wg_nsis_extract.c \
  "$WG"/Sources/Win32/wg_schannel.c "$WG"/Sources/Win32/wg_threading.c "$WG"/Sources/Win32/wg_sync.c \
  "$WG"/Sources/Win32/wg_win32_bitmap.c "$WG"/Sources/Win32/wg_win32_files.c \
  "$WG"/Sources/Win32/wg_win32_gdi.c "$WG"/Sources/Win32/wg_win32_windows.c \
  "$WG"/Sources/Win32/wg_winhttp.c "$WG"/Sources/Win32/wg_winsock.c \
  "$WG"/Sources/Win32/wg_d3d11.c "$WG"/Sources/Graphics/wg_dxbc.c \
  "$WG/Sources/LZMA/LzmaDec.c" \
  "$WG/Tests/wg_native_download_mac.m" \
  "$BUILD/WGMetalBackend.o" "$BUILD/mac_window_main.o" \
  "$BUILD/wg_blink_impl_macos.o" "$BLINKA" \
  -framework Security -framework CoreFoundation -framework Foundation \
  -framework CoreGraphics -framework CoreText \
  -framework Cocoa -framework Metal -framework QuartzCore \
  -framework AVFoundation -framework CoreVideo -framework CoreMedia -framework CoreImage \
  -o "$BUILD/wineglass_window"
echo "built: $BUILD/wineglass_window"
