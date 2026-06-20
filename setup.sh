#!/bin/bash
set -e

echo "=== WineGlass Project Setup ==="

# Check for Xcode
if ! command -v xcodebuild &>/dev/null; then
    echo "ERROR: Xcode not found. Install from the App Store."
    exit 1
fi

echo "Xcode: $(xcodebuild -version | head -1)"

# Try xcodegen first
if command -v xcodegen &>/dev/null; then
    echo "Using XcodeGen to generate project..."
    xcodegen generate
    echo "Done! Open WineGlass.xcodeproj in Xcode."
else
    echo ""
    echo "XcodeGen not found. Install it for automatic project generation:"
    echo "  brew install xcodegen"
    echo ""
    echo "Then run: xcodegen generate"
    echo ""
    echo "Alternatively, create the Xcode project manually:"
    echo "  1. Open Xcode -> File -> New -> Project -> iOS -> App"
    echo "  2. Name it 'WineGlass', set language to Objective-C"
    echo "  3. Delete the auto-generated source files"
    echo "  4. Drag the Sources/ folder into the project navigator"
    echo "  5. Add Header Search Paths in Build Settings:"
    echo "     \$(SRCROOT)/Sources/Core"
    echo "     \$(SRCROOT)/Sources/PE"
    echo "     \$(SRCROOT)/Sources/CPU"
    echo "     \$(SRCROOT)/Sources/Memory"
    echo "     \$(SRCROOT)/Sources/Win32"
    echo "     \$(SRCROOT)/Sources/Graphics"
    echo "     \$(SRCROOT)/Sources/App"
    echo "  6. Link frameworks: Metal, MetalKit, QuartzCore, UIKit, GameController, CoreHaptics"
    echo "  7. Set Info.plist to Sources/App/Info.plist"
    echo "  8. Set deployment target to iOS 17.0"
    echo "  9. Build and run on device or simulator"
fi

echo ""
echo "=== Project Structure ==="
echo "Phase 1: Sources/App/        - iOS app shell + Metal rendering"
echo "Phase 2: Sources/PE/         - Windows PE executable loader"
echo "Phase 3: Sources/CPU/        - x86-64 instruction decoder + interpreter"
echo "Phase 4: Sources/Win32/      - Win32 API stub layer (kernel32, user32, ntdll)"
echo "Phase 5: Sources/Graphics/   - D3D -> Metal graphics bridge (future)"
echo "Core:    Sources/Core/       - Engine orchestrator, logging, self-tests"
echo "         Sources/Memory/     - Virtual memory manager"
