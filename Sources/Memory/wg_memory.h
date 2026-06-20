#ifndef WG_MEMORY_H
#define WG_MEMORY_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#define WG_MEM_READ   0x01
#define WG_MEM_WRITE  0x02
#define WG_MEM_EXEC   0x04

#define WG_PAGE_SIZE  4096
#define WG_MAX_REGIONS 1024

typedef struct {
    uint64_t base;
    uint64_t size;
    uint32_t prot;
    uint8_t *data;
} WGMemRegion;

typedef struct {
    WGMemRegion regions[WG_MAX_REGIONS];
    int         num_regions;
    uint64_t    total_size;
} WGMemorySpace;

WGMemorySpace *wg_memory_create(uint64_t max_size);
void           wg_memory_destroy(WGMemorySpace *mem);

bool     wg_memory_map(WGMemorySpace *mem, uint64_t base, uint64_t size, uint32_t prot);
bool     wg_memory_unmap(WGMemorySpace *mem, uint64_t base);
bool     wg_memory_protect(WGMemorySpace *mem, uint64_t base, uint64_t size, uint32_t prot);

uint8_t  wg_memory_read_u8(WGMemorySpace *mem, uint64_t addr);
uint16_t wg_memory_read_u16(WGMemorySpace *mem, uint64_t addr);
uint32_t wg_memory_read_u32(WGMemorySpace *mem, uint64_t addr);
uint64_t wg_memory_read_u64(WGMemorySpace *mem, uint64_t addr);

void wg_memory_write_u8(WGMemorySpace *mem, uint64_t addr, uint8_t val);
void wg_memory_write_u16(WGMemorySpace *mem, uint64_t addr, uint16_t val);
void wg_memory_write_u32(WGMemorySpace *mem, uint64_t addr, uint32_t val);
void wg_memory_write_u64(WGMemorySpace *mem, uint64_t addr, uint64_t val);

bool wg_memory_read(WGMemorySpace *mem, uint64_t addr, void *buf, size_t len);
bool wg_memory_write(WGMemorySpace *mem, uint64_t addr, const void *buf, size_t len);

#endif
