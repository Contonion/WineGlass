// WineGlass GDI validation program — a minimal 32-bit Win32 GUI app.
// Deliberately straight-line code (no heavy pointer loops) so it exercises
// the translation layer's window + GDI + compositor path without tripping
// blink's deep-loop desync. Draws into the client area via GetDC.
//
// Build:
//   i686-w64-mingw32-gcc -O1 -ffreestanding -nostdlib -e _start_ \
//     -Wl,--subsystem,windows -o WGTest.exe gdi_test.c \
//     -lkernel32 -luser32 -lgdi32

#include <windows.h>

// Global zero-initialized class struct (lives in .bss, no memset needed).
static WNDCLASSW g_wc;

static LRESULT CALLBACK WndProc(HWND h, UINT m, WPARAM w, LPARAM l) {
    if (m == WM_DESTROY) { PostQuitMessage(0); return 0; }
    return DefWindowProcW(h, m, w, l);
}

void _start_(void) {
    HINSTANCE hInst = GetModuleHandleW(0);

    g_wc.lpfnWndProc   = WndProc;
    g_wc.hInstance     = hInst;
    g_wc.lpszClassName = L"WGTest";
    g_wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    RegisterClassW(&g_wc);

    HWND hwnd = CreateWindowExW(
        0, L"WGTest", L"WineGlass GDI Test",
        WS_OVERLAPPEDWINDOW,
        40, 60, 400, 300,
        0, 0, hInst, 0);

    ShowWindow(hwnd, SW_SHOW);

    // Draw directly into the client area (phase-1: no WM_PAINT needed).
    HDC hdc = GetDC(hwnd);

    HBRUSH blue = CreateSolidBrush(RGB(40, 90, 200));
    RECT bar = { 20, 20, 360, 70 };
    FillRect(hdc, &bar, blue);

    SetBkMode(hdc, TRANSPARENT);
    SetTextColor(hdc, RGB(255, 255, 255));
    TextOutW(hdc, 34, 36, L"Hello from x86 on iPhone!", 25);

    SetTextColor(hdc, RGB(20, 20, 20));
    TextOutW(hdc, 34, 110, L"WineGlass translation layer", 27);
    TextOutW(hdc, 34, 134, L"GDI -> Metal -> screen", 22);

    // A horizontal rule and a small filled square.
    HBRUSH green = CreateSolidBrush(RGB(40, 170, 90));
    RECT sq = { 34, 170, 84, 220 };
    FillRect(hdc, &sq, green);

    MoveToEx(hdc, 20, 160, 0);
    LineTo(hdc, 360, 160);

    ReleaseDC(hwnd, hdc);

    // Simple message loop — engine pauses here; the drawing persists.
    MSG msg;
    while (GetMessageW(&msg, 0, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    ExitProcess(0);
}
