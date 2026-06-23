#include "wg_pe_loader.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#define TAG "PE"

// PE format constants
#define IMAGE_DOS_SIGNATURE       0x5A4D     // "MZ"
#define IMAGE_NT_SIGNATURE        0x00004550 // "PE\0\0"
#define IMAGE_FILE_MACHINE_AMD64  0x8664
#define IMAGE_FILE_MACHINE_I386   0x014C

// Optional header magic
#define IMAGE_NT_OPTIONAL_HDR32_MAGIC 0x10B
#define IMAGE_NT_OPTIONAL_HDR64_MAGIC 0x20B

// Directory entry indices
#define IMAGE_DIRECTORY_ENTRY_EXPORT    0
#define IMAGE_DIRECTORY_ENTRY_IMPORT    1
#define IMAGE_DIRECTORY_ENTRY_BASERELOC 5
#define IMAGE_DIRECTORY_ENTRY_TLS       9
#define IMAGE_DIRECTORY_ENTRY_IAT       12

// Structures matching the PE spec exactly
#pragma pack(push, 1)

typedef struct {
    uint16_t e_magic;
    uint16_t e_cblp;
    uint16_t e_cp;
    uint16_t e_crlc;
    uint16_t e_cparhdr;
    uint16_t e_minalloc;
    uint16_t e_maxalloc;
    uint16_t e_ss;
    uint16_t e_sp;
    uint16_t e_csum;
    uint16_t e_ip;
    uint16_t e_cs;
    uint16_t e_lfarlc;
    uint16_t e_ovno;
    uint16_t e_res[4];
    uint16_t e_oemid;
    uint16_t e_oeminfo;
    uint16_t e_res2[10];
    int32_t  e_lfanew;
} DOSHeader;

typedef struct {
    uint16_t Machine;
    uint16_t NumberOfSections;
    uint32_t TimeDateStamp;
    uint32_t PointerToSymbolTable;
    uint32_t NumberOfSymbols;
    uint16_t SizeOfOptionalHeader;
    uint16_t Characteristics;
} COFFHeader;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint64_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint64_t SizeOfStackReserve;
    uint64_t SizeOfStackCommit;
    uint64_t SizeOfHeapReserve;
    uint64_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} OptionalHeader64;

typedef struct {
    uint16_t Magic;
    uint8_t  MajorLinkerVersion;
    uint8_t  MinorLinkerVersion;
    uint32_t SizeOfCode;
    uint32_t SizeOfInitializedData;
    uint32_t SizeOfUninitializedData;
    uint32_t AddressOfEntryPoint;
    uint32_t BaseOfCode;
    uint32_t BaseOfData;
    uint32_t ImageBase;
    uint32_t SectionAlignment;
    uint32_t FileAlignment;
    uint16_t MajorOperatingSystemVersion;
    uint16_t MinorOperatingSystemVersion;
    uint16_t MajorImageVersion;
    uint16_t MinorImageVersion;
    uint16_t MajorSubsystemVersion;
    uint16_t MinorSubsystemVersion;
    uint32_t Win32VersionValue;
    uint32_t SizeOfImage;
    uint32_t SizeOfHeaders;
    uint32_t CheckSum;
    uint16_t Subsystem;
    uint16_t DllCharacteristics;
    uint32_t SizeOfStackReserve;
    uint32_t SizeOfStackCommit;
    uint32_t SizeOfHeapReserve;
    uint32_t SizeOfHeapCommit;
    uint32_t LoaderFlags;
    uint32_t NumberOfRvaAndSizes;
} OptionalHeader32;

typedef struct {
    uint32_t VirtualAddress;
    uint32_t Size;
} DataDirectory;

typedef struct {
    char     Name[8];
    uint32_t VirtualSize;
    uint32_t VirtualAddress;
    uint32_t SizeOfRawData;
    uint32_t PointerToRawData;
    uint32_t PointerToRelocations;
    uint32_t PointerToLinenumbers;
    uint16_t NumberOfRelocations;
    uint16_t NumberOfLinenumbers;
    uint32_t Characteristics;
} SectionHeader;

typedef struct {
    uint32_t OriginalFirstThunk;
    uint32_t TimeDateStamp;
    uint32_t ForwarderChain;
    uint32_t Name;
    uint32_t FirstThunk;
} ImportDescriptor;

#pragma pack(pop)

static const uint8_t *rva_to_ptr(const WGPEImage *img, uint32_t rva) {
    for (int i = 0; i < img->num_sections; i++) {
        const WGPESection *s = &img->sections[i];
        if (rva >= s->virtual_address && rva < s->virtual_address + s->raw_size) {
            uint32_t offset = rva - s->virtual_address;
            if (s->data && offset < s->raw_size) {
                return s->data + offset;
            }
        }
    }
    return NULL;
}

static bool parse_imports(WGPEImage *img, uint32_t import_rva, uint32_t import_size) {
    if (import_rva == 0 || import_size == 0) return true;

    const uint8_t *import_ptr = rva_to_ptr(img, import_rva);
    if (!import_ptr) {
        WG_LOGW(TAG, "Import directory RVA 0x%X not found in %d sections",
                import_rva, img->num_sections);
        for (int dbg = 0; dbg < img->num_sections; dbg++) {
            WG_LOGW(TAG, "  sec[%d] '%s': VA=0x%X rawsz=0x%X data=%p",
                    dbg, img->sections[dbg].name,
                    img->sections[dbg].virtual_address,
                    img->sections[dbg].raw_size,
                    (void*)img->sections[dbg].data);
        }
        return true;
    }

    const ImportDescriptor *desc = (const ImportDescriptor *)import_ptr;
    img->num_imports = 0;

    while (desc->Name != 0 && img->num_imports < PE_MAX_IMPORTS) {
        const char *dll_name = (const char *)rva_to_ptr(img, desc->Name);
        if (!dll_name) break;

        WGPEImportDll *imp = &img->imports[img->num_imports];
        strncpy(imp->dll_name, dll_name, sizeof(imp->dll_name) - 1);
        imp->num_functions = 0;

        uint32_t thunk_rva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
        uint32_t iat_rva = desc->FirstThunk;

        if (img->is_64bit) {
            const uint64_t *thunk = (const uint64_t *)rva_to_ptr(img, thunk_rva);
            if (!thunk) { desc++; continue; }

            while (*thunk && imp->num_functions < PE_MAX_IMPORT_FUNCS) {
                WGPEImportFunc *func = &imp->functions[imp->num_functions];
                func->iat_rva = iat_rva + (uint32_t)(imp->num_functions * sizeof(uint64_t));

                if (*thunk & 0x8000000000000000ULL) {
                    func->ordinal = (uint16_t)(*thunk & 0xFFFF);
                    snprintf(func->name, sizeof(func->name), "Ordinal_%u", func->ordinal);
                } else {
                    uint32_t hint_rva = (uint32_t)(*thunk & 0x7FFFFFFF);
                    const uint8_t *hint_ptr = rva_to_ptr(img, hint_rva);
                    if (hint_ptr) {
                        func->ordinal = *(const uint16_t *)hint_ptr;
                        strncpy(func->name, (const char *)(hint_ptr + 2), sizeof(func->name) - 1);
                    }
                }
                imp->num_functions++;
                thunk++;
            }
        } else {
            const uint32_t *thunk = (const uint32_t *)rva_to_ptr(img, thunk_rva);
            if (!thunk) { desc++; continue; }

            while (*thunk && imp->num_functions < PE_MAX_IMPORT_FUNCS) {
                WGPEImportFunc *func = &imp->functions[imp->num_functions];
                func->iat_rva = iat_rva + (uint32_t)(imp->num_functions * sizeof(uint32_t));

                if (*thunk & 0x80000000) {
                    func->ordinal = (uint16_t)(*thunk & 0xFFFF);
                    snprintf(func->name, sizeof(func->name), "Ordinal_%u", func->ordinal);
                } else {
                    uint32_t hint_rva = *thunk & 0x7FFFFFFF;
                    const uint8_t *hint_ptr = rva_to_ptr(img, hint_rva);
                    if (hint_ptr) {
                        func->ordinal = *(const uint16_t *)hint_ptr;
                        strncpy(func->name, (const char *)(hint_ptr + 2), sizeof(func->name) - 1);
                    }
                }
                imp->num_functions++;
                thunk++;
            }
        }

        img->num_imports++;
        desc++;
    }

    return true;
}

WGPEImage *wg_pe_load_memory(const uint8_t *data, size_t size) {
    if (size < sizeof(DOSHeader)) {
        WG_LOGE(TAG, "File too small for DOS header");
        return NULL;
    }

    const DOSHeader *dos = (const DOSHeader *)data;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        WG_LOGE(TAG, "Invalid DOS signature: 0x%04X (expected 0x%04X)", dos->e_magic, IMAGE_DOS_SIGNATURE);
        return NULL;
    }

    uint32_t pe_offset = dos->e_lfanew;
    if (pe_offset + 4 > size) {
        WG_LOGE(TAG, "PE offset out of bounds");
        return NULL;
    }

    uint32_t pe_sig = *(const uint32_t *)(data + pe_offset);
    if (pe_sig != IMAGE_NT_SIGNATURE) {
        WG_LOGE(TAG, "Invalid PE signature: 0x%08X", pe_sig);
        return NULL;
    }

    const COFFHeader *coff = (const COFFHeader *)(data + pe_offset + 4);
    WG_LOGI(TAG, "Machine: %s (0x%04X), Sections: %d",
            wg_pe_machine_name(coff->Machine), coff->Machine, coff->NumberOfSections);

    WGPEImage *img = calloc(1, sizeof(WGPEImage));
    if (!img) return NULL;

    img->raw_data = malloc(size);
    if (!img->raw_data) { free(img); return NULL; }
    memcpy(img->raw_data, data, size);
    img->raw_size = size;
    img->machine = coff->Machine;

    const uint8_t *opt_hdr = (const uint8_t *)coff + sizeof(COFFHeader);
    uint16_t opt_magic = *(const uint16_t *)opt_hdr;

    DataDirectory *directories = NULL;
    uint32_t num_directories = 0;

    if (opt_magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        img->is_64bit = true;
        const OptionalHeader64 *opt = (const OptionalHeader64 *)opt_hdr;
        img->entry_point = opt->AddressOfEntryPoint;
        img->image_base = opt->ImageBase;
        img->size_of_image = opt->SizeOfImage;
        img->size_of_headers = opt->SizeOfHeaders;
        img->subsystem = opt->Subsystem;
        img->dll_characteristics = opt->DllCharacteristics;
        num_directories = opt->NumberOfRvaAndSizes;
        directories = (DataDirectory *)(opt_hdr + sizeof(OptionalHeader64));
        WG_LOGI(TAG, "PE32+ (64-bit), ImageBase=0x%llx, Entry=0x%08x",
                (unsigned long long)img->image_base, img->entry_point);
    } else if (opt_magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        img->is_64bit = false;
        const OptionalHeader32 *opt = (const OptionalHeader32 *)opt_hdr;
        img->entry_point = opt->AddressOfEntryPoint;
        img->image_base = opt->ImageBase;
        img->size_of_image = opt->SizeOfImage;
        img->size_of_headers = opt->SizeOfHeaders;
        img->subsystem = opt->Subsystem;
        img->dll_characteristics = opt->DllCharacteristics;
        num_directories = opt->NumberOfRvaAndSizes;
        directories = (DataDirectory *)(opt_hdr + sizeof(OptionalHeader32));
        WG_LOGI(TAG, "PE32 (32-bit), ImageBase=0x%08x, Entry=0x%08x",
                (uint32_t)img->image_base, img->entry_point);
    } else {
        WG_LOGE(TAG, "Unknown optional header magic: 0x%04X", opt_magic);
        wg_pe_image_free(img);
        return NULL;
    }

    WG_LOGI(TAG, "Subsystem: %s", wg_pe_subsystem_name(img->subsystem));

    // Parse sections
    const SectionHeader *sec_hdrs = (const SectionHeader *)(opt_hdr + coff->SizeOfOptionalHeader);
    img->num_sections = coff->NumberOfSections;
    if (img->num_sections > PE_MAX_SECTIONS) img->num_sections = PE_MAX_SECTIONS;

    for (int i = 0; i < img->num_sections; i++) {
        const SectionHeader *sh = &sec_hdrs[i];
        WGPESection *sec = &img->sections[i];

        memcpy(sec->name, sh->Name, 8);
        sec->name[8] = '\0';
        sec->virtual_size = sh->VirtualSize;
        sec->virtual_address = sh->VirtualAddress;
        sec->raw_size = sh->SizeOfRawData;
        sec->raw_offset = sh->PointerToRawData;
        sec->characteristics = sh->Characteristics;

        if (sh->PointerToRawData > 0 && sh->SizeOfRawData > 0 &&
            sh->PointerToRawData + sh->SizeOfRawData <= size) {
            sec->data = img->raw_data + sh->PointerToRawData;
        }
    }

    // Parse imports
    if (num_directories > IMAGE_DIRECTORY_ENTRY_IMPORT) {
        DataDirectory *imp_dir = &directories[IMAGE_DIRECTORY_ENTRY_IMPORT];
        WG_LOGI(TAG, "Import directory: RVA=0x%X, Size=0x%X",
                imp_dir->VirtualAddress, imp_dir->Size);
        parse_imports(img, imp_dir->VirtualAddress, imp_dir->Size);
    }

    // Record export & base-reloc directory locations (used when loading DLLs).
    if (num_directories > IMAGE_DIRECTORY_ENTRY_EXPORT) {
        img->export_rva  = directories[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        img->export_size = directories[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    }
    if (num_directories > IMAGE_DIRECTORY_ENTRY_BASERELOC) {
        img->reloc_rva  = directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
        img->reloc_size = directories[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
    }
    if (num_directories > IMAGE_DIRECTORY_ENTRY_TLS) {
        img->tls_rva  = directories[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
        img->tls_size = directories[IMAGE_DIRECTORY_ENTRY_TLS].Size;
    }

    return img;
}

WGPEImage *wg_pe_load_file(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) {
        WG_LOGE(TAG, "Cannot open file: %s", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long file_size = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (file_size <= 0 || file_size > 512 * 1024 * 1024) {
        WG_LOGE(TAG, "Invalid file size: %ld", file_size);
        fclose(f);
        return NULL;
    }

    uint8_t *data = malloc(file_size);
    if (!data) {
        fclose(f);
        return NULL;
    }

    size_t read = fread(data, 1, file_size, f);
    fclose(f);

    if ((long)read != file_size) {
        free(data);
        return NULL;
    }

    WGPEImage *img = wg_pe_load_memory(data, file_size);
    free(data);
    return img;
}

void wg_pe_image_free(WGPEImage *image) {
    if (!image) return;
    free(image->raw_data);
    free(image);
}

const char *wg_pe_machine_name(uint16_t machine) {
    switch (machine) {
        case IMAGE_FILE_MACHINE_AMD64: return "x86-64";
        case IMAGE_FILE_MACHINE_I386:  return "x86";
        case 0xAA64:                   return "ARM64";
        default:                       return "Unknown";
    }
}

const char *wg_pe_subsystem_name(uint16_t subsystem) {
    switch (subsystem) {
        case 1:  return "Native";
        case 2:  return "Windows GUI";
        case 3:  return "Windows Console";
        case 5:  return "OS/2 Console";
        case 7:  return "POSIX Console";
        case 9:  return "Windows CE";
        case 10: return "EFI Application";
        default: return "Unknown";
    }
}
