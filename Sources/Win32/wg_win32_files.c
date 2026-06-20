#include "wg_win32_files.h"
#include "wg_log.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>

#define TAG "Files"

static char s_exe_path[1024] = {0};
static char s_exe_dir[1024] = {0};

typedef struct {
    FILE    *fp;
    uint32_t handle;
    bool     in_use;
    char     path[512];
} WGFileEntry;

static WGFileEntry s_files[WG_MAX_FILE_HANDLES] = {0};
static uint32_t s_next_handle = WG_FILE_HANDLE_BASE;

void wg_files_set_exe_path(const char *path) {
    strncpy(s_exe_path, path, sizeof(s_exe_path) - 1);
    strncpy(s_exe_dir, path, sizeof(s_exe_dir) - 1);
    char *last_slash = strrchr(s_exe_dir, '/');
    if (last_slash) *(last_slash + 1) = '\0';
    WG_LOGI(TAG, "EXE path: %s", s_exe_path);
    WG_LOGI(TAG, "EXE dir: %s", s_exe_dir);
}

static void fix_separators(char *path) {
    for (char *p = path; *p; p++) {
        if (*p == '\\') *p = '/';
    }
}

const char *wg_files_map_path(uint32_t guest_path_addr, void *blink,
                               char *buf, int bufsize) {
    // Map known Windows paths to iOS paths
    if (strcasecmp(buf, "C:\\a.exe") == 0 ||
        strcasecmp(buf, "C:/a.exe") == 0) {
        return s_exe_path;
    }

    // Map C:\Temp\ to the exe's directory
    if (strncasecmp(buf, "C:\\Temp\\", 8) == 0 ||
        strncasecmp(buf, "C:/Temp/", 8) == 0) {
        static char mapped[1024];
        snprintf(mapped, sizeof(mapped), "%s%s", s_exe_dir, buf + 8);
        fix_separators(mapped);
        return mapped;
    }
    if (strncasecmp(buf, "C:\\Temp", 7) == 0 && (buf[7] == 0 || buf[7] == '\\')) {
        static char mapped2[1024];
        snprintf(mapped2, sizeof(mapped2), "%s%s", s_exe_dir, buf + 7 ? buf + 7 : "");
        fix_separators(mapped2);
        return mapped2;
    }

    // Map C:\Windows\ paths
    if (strncasecmp(buf, "C:\\Windows\\", 11) == 0 ||
        strncasecmp(buf, "C:/Windows/", 11) == 0) {
        return NULL;
    }

    // Everything else: relative to exe dir
    static char rel_mapped[1024];
    const char *p = buf;
    if (p[1] == ':') p += 2;
    while (*p == '\\' || *p == '/') p++;
    snprintf(rel_mapped, sizeof(rel_mapped), "%s%s", s_exe_dir, p);
    fix_separators(rel_mapped);
    return rel_mapped;
}

uint32_t wg_files_create(const char *real_path, uint32_t access, uint32_t creation) {
    if (!real_path || !real_path[0]) return 0xFFFFFFFF;

    // Determine open mode from creation disposition
    // CREATE_ALWAYS=2, OPEN_EXISTING=3, OPEN_ALWAYS=4, TRUNCATE_EXISTING=5
    const char *mode;
    switch (creation) {
        case 2: mode = "wb+"; break;  // CREATE_ALWAYS
        case 3: mode = "rb";  break;  // OPEN_EXISTING
        case 4: mode = "ab+"; break;  // OPEN_ALWAYS
        case 5: mode = "wb";  break;  // TRUNCATE_EXISTING
        default: mode = "rb"; break;
    }

    // If access includes write (0x40000000 = GENERIC_WRITE)
    if ((access & 0x40000000) && creation == 3) {
        mode = "rb+";
    }

    FILE *fp = fopen(real_path, mode);
    if (!fp && (creation == 2 || creation == 4)) {
        // CREATE_ALWAYS or OPEN_ALWAYS — try creating parent directories
        char parent[1024];
        strncpy(parent, real_path, sizeof(parent) - 1);
        char *last_sep = strrchr(parent, '/');
        if (last_sep) {
            *last_sep = '\0';
            mkdir(parent, 0755); // create parent dir if needed
            fp = fopen(real_path, mode); // retry
        }
    }
    if (!fp) {
        WG_LOGD(TAG, "Open failed: %s (mode=%s)", real_path, mode);
        return 0xFFFFFFFF;
    }

    // Find a free slot
    for (int i = 0; i < WG_MAX_FILE_HANDLES; i++) {
        if (!s_files[i].in_use) {
            s_files[i].fp = fp;
            s_files[i].handle = s_next_handle++;
            s_files[i].in_use = true;
            strncpy(s_files[i].path, real_path, sizeof(s_files[i].path) - 1);
            WG_LOGI(TAG, "Opened: %s -> handle 0x%X", real_path, s_files[i].handle);
            return s_files[i].handle;
        }
    }

    fclose(fp);
    return 0xFFFFFFFF;
}

static WGFileEntry *find_file(uint32_t handle) {
    for (int i = 0; i < WG_MAX_FILE_HANDLES; i++) {
        if (s_files[i].in_use && s_files[i].handle == handle)
            return &s_files[i];
    }
    return NULL;
}

bool wg_files_read(uint32_t handle, void *buf, uint32_t bytes, uint32_t *bytes_read) {
    WGFileEntry *f = find_file(handle);
    if (!f) return false;
    size_t n = fread(buf, 1, bytes, f->fp);
    if (bytes_read) *bytes_read = (uint32_t)n;
    return true;
}

bool wg_files_write(uint32_t handle, const void *buf, uint32_t bytes, uint32_t *bytes_written) {
    WGFileEntry *f = find_file(handle);
    if (!f) return false;
    size_t n = fwrite(buf, 1, bytes, f->fp);
    if (bytes_written) *bytes_written = (uint32_t)n;
    return true;
}

uint32_t wg_files_get_size(uint32_t handle) {
    WGFileEntry *f = find_file(handle);
    if (!f) return 0xFFFFFFFF;
    long pos = ftell(f->fp);
    fseek(f->fp, 0, SEEK_END);
    long size = ftell(f->fp);
    fseek(f->fp, pos, SEEK_SET);
    return (uint32_t)size;
}

uint32_t wg_files_set_pointer(uint32_t handle, int32_t distance, uint32_t method) {
    WGFileEntry *f = find_file(handle);
    if (!f) return 0xFFFFFFFF;
    int whence;
    switch (method) {
        case 0: whence = SEEK_SET; break;
        case 1: whence = SEEK_CUR; break;
        case 2: whence = SEEK_END; break;
        default: whence = SEEK_SET; break;
    }
    fseek(f->fp, distance, whence);
    return (uint32_t)ftell(f->fp);
}

void wg_files_prepopulate_nsis_data(const char *exe_path, const char *tmp_path) {
    // Find the NSIS data section in the exe and copy it to the tmp file.
    // NSIS searches for 'NullsoftInst' marker, then reads the header
    // which tells it how much data follows.
    FILE *exe = fopen(exe_path, "rb");
    if (!exe) return;

    fseek(exe, 0, SEEK_END);
    long exe_size = ftell(exe);
    fseek(exe, 0, SEEK_SET);

    // Search for NullsoftInst marker
    uint8_t *exe_data = malloc(exe_size);
    if (!exe_data) { fclose(exe); return; }
    fread(exe_data, 1, exe_size, exe);
    fclose(exe);

    long nsi_offset = -1;
    for (long i = 0; i < exe_size - 16; i++) {
        if (memcmp(exe_data + i, "NullsoftInst", 12) == 0) {
            nsi_offset = i;
            break;
        }
    }

    if (nsi_offset < 0) {
        WG_LOGW("Files", "No NullsoftInst marker found in exe");
        free(exe_data);
        return;
    }

    // Parse NSIS firstheader
    // +12: header_length (compressed header size)
    // +16: archive_size (total data including header)
    uint32_t header_len, archive_size;
    memcpy(&header_len, exe_data + nsi_offset + 12, 4);
    memcpy(&archive_size, exe_data + nsi_offset + 16, 4);

    // Data starts at nsi_offset + 20 (after firstheader)
    long data_start = nsi_offset + 20;
    // File data starts after the compressed header
    long file_data_offset = data_start + header_len;
    long file_data_size = archive_size - header_len;

    if (file_data_offset < 0 || file_data_offset >= exe_size || file_data_size <= 0) {
        WG_LOGW("Files", "Invalid NSIS data layout");
        free(exe_data);
        return;
    }

    if (file_data_offset + file_data_size > exe_size) {
        file_data_size = exe_size - file_data_offset;
    }

    // Write the file data section to the tmp file
    FILE *tmp = fopen(tmp_path, "wb");
    if (!tmp) {
        WG_LOGW("Files", "Can't create prepopulated tmp file");
        free(exe_data);
        return;
    }

    fwrite(exe_data + file_data_offset, 1, file_data_size, tmp);
    fclose(tmp);
    free(exe_data);

    WG_LOGI("Files", "Pre-populated NSIS data: %ld bytes at offset %ld -> %s",
            file_data_size, file_data_offset, tmp_path);
}

bool wg_files_close(uint32_t handle) {
    WGFileEntry *f = find_file(handle);
    if (!f) return false;
    fclose(f->fp);
    f->in_use = false;
    WG_LOGD(TAG, "Closed handle 0x%X", handle);
    return true;
}
