#include "wg_nsis_extract.h"
#include "wg_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <compression.h>

#define TAG "NSISExtract"

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
