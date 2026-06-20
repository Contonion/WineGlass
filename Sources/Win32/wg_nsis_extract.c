#include "wg_nsis_extract.h"
#include "wg_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <compression.h>

#define TAG "NSISExtract"

// Decompress the entire NSIS outer LZMA stream from the .exe and
// write the decompressed data to the .tmp file. This replaces
// NSIS's own x86 LZMA decompressor which has accuracy issues in
// blink's 32-bit compatibility mode.
bool wg_nsis_decompress_outer_stream(const char *exe_path,
                                      const char *tmp_path) {
    FILE *exe_fp = fopen(exe_path, "rb");
    if (!exe_fp) return false;

    fseek(exe_fp, 0, SEEK_END);
    long exe_size = ftell(exe_fp);
    fseek(exe_fp, 0, SEEK_SET);

    uint8_t *exe_data = malloc(exe_size);
    if (!exe_data) { fclose(exe_fp); return false; }
    fread(exe_data, 1, exe_size, exe_fp);
    fclose(exe_fp);

    // Find NullsoftInst marker
    long nsi = -1;
    for (long i = 0; i < exe_size - 16; i++) {
        if (memcmp(exe_data + i, "NullsoftInst", 12) == 0) {
            nsi = i; break;
        }
    }
    if (nsi < 0) {
        WG_LOGE(TAG, "No NullsoftInst marker");
        free(exe_data);
        return false;
    }

    uint32_t hdr_len, arc_size;
    memcpy(&hdr_len, exe_data + nsi + 12, 4);
    memcpy(&arc_size, exe_data + nsi + 16, 4);
    long data_start = nsi + 20;

    WG_LOGI(TAG, "NSIS: hdr_len=%u, arc_size=%u, data_start=%ld",
            hdr_len, arc_size, data_start);

    // The compressed data starts at data_start
    // It's one LZMA stream: first hdr_len bytes decompress to the header,
    // then the rest decompresses to the file data (goes into .tmp)

    // The entire archive (arc_size bytes) is the outer LZMA stream
    long compressed_size = arc_size;
    if (data_start + compressed_size > exe_size) {
        compressed_size = exe_size - data_start;
    }

    // Decompress using Apple's framework
    // The output could be up to 10x the compressed size
    size_t dst_capacity = compressed_size * 10;
    if (dst_capacity > 100 * 1024 * 1024) dst_capacity = 100 * 1024 * 1024;

    uint8_t *dst_buf = malloc(dst_capacity);
    if (!dst_buf) { free(exe_data); return false; }

    uint8_t *src = exe_data + data_start;

    // Try LZMA decompression
    size_t decompressed = compression_decode_buffer(
        dst_buf, dst_capacity,
        src, compressed_size,
        NULL, COMPRESSION_LZMA);

    if (decompressed == 0 || decompressed >= dst_capacity) {
        // Try skipping LZMA properties (5 bytes)
        if (compressed_size > 5) {
            decompressed = compression_decode_buffer(
                dst_buf, dst_capacity,
                src + 5, compressed_size - 5,
                NULL, COMPRESSION_LZMA);
        }
    }

    if (decompressed == 0 || decompressed >= dst_capacity) {
        // Try ZLIB
        decompressed = compression_decode_buffer(
            dst_buf, dst_capacity,
            src, compressed_size,
            NULL, COMPRESSION_ZLIB);
    }

    free(exe_data);

    if (decompressed == 0 || decompressed >= dst_capacity) {
        WG_LOGE(TAG, "Outer stream decompression failed");
        free(dst_buf);
        return false;
    }

    WG_LOGI(TAG, "Outer stream: %ld compressed -> %zu decompressed",
            compressed_size, decompressed);

    // The decompressed data contains:
    // [header: hdr_len bytes] [file data blocks]
    // The .tmp should contain ONLY the file data blocks (after the header)
    if (decompressed <= hdr_len) {
        WG_LOGE(TAG, "Decompressed too small: %zu <= %u", decompressed, hdr_len);
        free(dst_buf);
        return false;
    }

    // Write file data portion to .tmp
    FILE *tmp_fp = fopen(tmp_path, "wb");
    if (!tmp_fp) { free(dst_buf); return false; }

    size_t file_data_size = decompressed - hdr_len;
    fwrite(dst_buf + hdr_len, 1, file_data_size, tmp_fp);
    fclose(tmp_fp);

    WG_LOGI(TAG, "Wrote %zu bytes of file data to %s", file_data_size, tmp_path);
    free(dst_buf);
    return true;
}

bool wg_nsis_extract_file(const char *data_tmp_path,
                           uint32_t data_offset,
                           const char *output_path) {
    FILE *data_fp = fopen(data_tmp_path, "rb");
    if (!data_fp) {
        WG_LOGE(TAG, "Can't open data file: %s", data_tmp_path);
        return false;
    }

    // Seek to the file's data block
    fseek(data_fp, data_offset, SEEK_SET);

    // NSIS data block format:
    // [4 bytes] block header — high bit indicates if compressed
    //   If bit 31 set: stored uncompressed, size = header & 0x7FFFFFFF
    //   If bit 31 clear: LZMA compressed, compressed_size = header value
    //   Followed by [4 bytes] decompressed size (in some NSIS versions)
    //   Then the compressed/raw data

    uint32_t block_header;
    if (fread(&block_header, 4, 1, data_fp) != 1) {
        fclose(data_fp);
        return false;
    }

    bool is_compressed = (block_header & 0x80000000) == 0;
    uint32_t data_size = block_header & 0x7FFFFFFF;

    WG_LOGI(TAG, "Block at offset %u: %s, size=%u",
            data_offset, is_compressed ? "compressed" : "raw", data_size);

    if (data_size == 0 || data_size > 50 * 1024 * 1024) {
        WG_LOGE(TAG, "Invalid block size: %u", data_size);
        fclose(data_fp);
        return false;
    }

    uint8_t *src_buf = malloc(data_size);
    if (!src_buf) { fclose(data_fp); return false; }

    size_t read = fread(src_buf, 1, data_size, data_fp);
    fclose(data_fp);

    if (read != data_size) {
        WG_LOGE(TAG, "Short read: got %zu, expected %u", read, data_size);
        free(src_buf);
        return false;
    }

    FILE *out_fp = fopen(output_path, "wb");
    if (!out_fp) {
        free(src_buf);
        return false;
    }

    if (!is_compressed) {
        // Raw/uncompressed — write directly
        fwrite(src_buf, 1, data_size, out_fp);
        WG_LOGI(TAG, "Extracted raw: %u bytes -> %s", data_size, output_path);
    } else {
        // LZMA compressed — use Apple's Compression framework
        // The NSIS LZMA stream starts with LZMA properties (5 bytes)
        // followed by compressed data. Apple's COMPRESSION_LZMA expects
        // raw LZMA data without the header.

        // Try decompressing with generous output buffer
        size_t dst_capacity = data_size * 20; // assume max 20x expansion
        if (dst_capacity < 1024 * 1024) dst_capacity = 1024 * 1024;
        if (dst_capacity > 50 * 1024 * 1024) dst_capacity = 50 * 1024 * 1024;

        uint8_t *dst_buf = malloc(dst_capacity);
        if (!dst_buf) {
            free(src_buf);
            fclose(out_fp);
            return false;
        }

        // Try COMPRESSION_LZMA first
        size_t decompressed = compression_decode_buffer(
            dst_buf, dst_capacity,
            src_buf, data_size,
            NULL, // scratch buffer
            COMPRESSION_LZMA);

        if (decompressed == 0 || decompressed == dst_capacity) {
            // LZMA failed — try with LZMA properties stripped (skip first 5 bytes)
            if (data_size > 5) {
                decompressed = compression_decode_buffer(
                    dst_buf, dst_capacity,
                    src_buf + 5, data_size - 5,
                    NULL,
                    COMPRESSION_LZMA);
            }
        }

        if (decompressed == 0 || decompressed == dst_capacity) {
            // Try ZLIB as fallback
            decompressed = compression_decode_buffer(
                dst_buf, dst_capacity,
                src_buf, data_size,
                NULL,
                COMPRESSION_ZLIB);
        }

        if (decompressed > 0 && decompressed < dst_capacity) {
            fwrite(dst_buf, 1, decompressed, out_fp);
            WG_LOGI(TAG, "Extracted: %u -> %zu bytes -> %s",
                    data_size, decompressed, output_path);
        } else {
            // Decompression failed — write raw data as fallback
            fwrite(src_buf, 1, data_size, out_fp);
            WG_LOGW(TAG, "Decompression failed, wrote raw %u bytes -> %s",
                    data_size, output_path);
        }

        free(dst_buf);
    }

    fclose(out_fp);
    free(src_buf);
    return true;
}
