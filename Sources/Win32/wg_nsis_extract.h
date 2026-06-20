#ifndef WG_NSIS_EXTRACT_H
#define WG_NSIS_EXTRACT_H

#include <stdint.h>
#include <stdbool.h>

// Native NSIS file extraction using Apple's Compression framework.
// Bypasses the x86 LZMA decompressor which has accuracy issues in
// blink's 32-bit compatibility mode.

// Extract a file from the NSIS data .tmp at the given offset.
// Returns true if extraction succeeded.
// Decompress the entire NSIS outer LZMA stream from the .exe
// and write the decompressed file data to the .tmp file.
bool wg_nsis_decompress_outer_stream(const char *exe_path,
                                      const char *tmp_path);

bool wg_nsis_extract_file(const char *data_tmp_path,
                           uint32_t data_offset,
                           const char *output_path);

#endif
