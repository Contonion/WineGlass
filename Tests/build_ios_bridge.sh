#!/bin/bash
# build_ios_bridge.sh — cross-compile the blink bridge object for iOS arm64.
#
# The Xcode app links two prebuilt artifacts (project.yml OTHER_LDFLAGS):
#   Vendor/blink/lib/wg_blink_impl.o   (this script)
#   Vendor/blink/lib/blink.a           (blink static lib — unchanged)
#
# blink.a does NOT need rebuilding for the real-threads work: our design keeps
# blink built with DISABLE_THREADS (its SMP locks deadlock our manual stepping)
# and tracks the per-thread Machine in the bridge's OWN __thread TLS. So only the
# BRIDGE object changes. Re-run this after editing Vendor/blink/wg_blink_impl.c,
# then rebuild the app in Xcode.
#
# Uses the full Xcode (not the CLT) for the iPhoneOS SDK.
set -e
WG="$(cd "$(dirname "$0")/.." && pwd)"

# Locate a full Xcode with the iPhoneOS SDK (CLT has only macOS).
XCODE_DEV=""
for x in /Applications/Xcode.app /Applications/Xcode-beta.app; do
  [ -d "$x/Contents/Developer/Platforms/iPhoneOS.platform" ] && XCODE_DEV="$x/Contents/Developer" && break
done
[ -n "$XCODE_DEV" ] || { echo "ERROR: no Xcode with iPhoneOS SDK found"; exit 1; }
SDK="$(ls -d "$XCODE_DEV/Platforms/iPhoneOS.platform/Developer/SDKs/iPhoneOS"*.sdk | tail -1)"
CLANG="$XCODE_DEV/Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
echo "SDK:   $SDK"

cp -f "$WG/Vendor/blink/lib/wg_blink_impl.o" "$WG/Vendor/blink/lib/wg_blink_impl.o.prethreads" 2>/dev/null || true

"$CLANG" -arch arm64 -isysroot "$SDK" -miphoneos-version-min=17.0 \
  -O1 -g -Wno-everything \
  -I"$WG/Vendor/blink/include" \
  -c "$WG/Vendor/blink/wg_blink_impl.c" \
  -o "$WG/Vendor/blink/lib/wg_blink_impl.o"

echo "built: Vendor/blink/lib/wg_blink_impl.o (iOS arm64, real-threads bridge)"
