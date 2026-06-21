#ifndef WG_NSIS_EXTRACT_H
#define WG_NSIS_EXTRACT_H

#include <stdint.h>
#include <stdbool.h>

// Native NSIS decompression using the LZMA SDK decoder (LzmaDec.c).
//
// SteamSetup-style NSIS installers decompress their entire data section (one
// solid raw-LZMA stream) into a temp file, then read each packed file from it
// by decompressed offset. blink's in-guest decode of that stream is unreliable
// (truncates), so we decompress it natively and pre-fill the temp file with the
// correct full data — NSIS then reads every file correctly.

// Find the NSIS data section in exe_path, decompress the whole solid LZMA
// stream, and write the resulting bytes to out_path. Returns true on success.
bool wg_nsis_prefill_datatmp(const char *exe_path, const char *out_path);

#endif
