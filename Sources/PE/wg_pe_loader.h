#ifndef WG_PE_LOADER_H
#define WG_PE_LOADER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define PE_MAX_SECTIONS     96
#define PE_MAX_IMPORTS      256
#define PE_MAX_IMPORT_FUNCS 4096

typedef struct {
    char     name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_offset;
    uint32_t characteristics;
    uint8_t *data;
} WGPESection;

typedef struct {
    char     name[256];
    uint16_t ordinal;
    uint32_t iat_rva;
} WGPEImportFunc;

typedef struct {
    char             dll_name[256];
    int              num_functions;
    WGPEImportFunc   functions[PE_MAX_IMPORT_FUNCS];
} WGPEImportDll;

typedef struct {
    // Headers
    uint64_t  image_base;
    uint32_t  entry_point;
    uint32_t  size_of_image;
    uint32_t  size_of_headers;
    uint16_t  subsystem;
    uint16_t  dll_characteristics;
    uint16_t  machine;
    bool      is_64bit;

    // Sections
    int         num_sections;
    WGPESection sections[PE_MAX_SECTIONS];

    // Imports
    int            num_imports;
    WGPEImportDll  imports[PE_MAX_IMPORTS];

    // Export & base-relocation directories (for loading DLLs / plug-ins)
    uint32_t  export_rva,  export_size;
    uint32_t  reloc_rva,   reloc_size;
    uint32_t  tls_rva,     tls_size;   // TLS directory (CRT thread-local setup)

    // Raw file data
    uint8_t *raw_data;
    size_t   raw_size;
} WGPEImage;

WGPEImage *wg_pe_load_file(const char *path);
WGPEImage *wg_pe_load_memory(const uint8_t *data, size_t size);
void       wg_pe_image_free(WGPEImage *image);

const char *wg_pe_machine_name(uint16_t machine);
const char *wg_pe_subsystem_name(uint16_t subsystem);

#endif
