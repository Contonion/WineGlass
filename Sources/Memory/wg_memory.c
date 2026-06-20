#include "wg_memory.h"
#include "wg_log.h"
#include <stdlib.h>
#include <string.h>

#define TAG "Mem"

WGMemorySpace *wg_memory_create(uint64_t max_size) {
    WGMemorySpace *mem = calloc(1, sizeof(WGMemorySpace));
    if (!mem) return NULL;
    mem->total_size = max_size;
    return mem;
}

void wg_memory_destroy(WGMemorySpace *mem) {
    if (!mem) return;
    for (int i = 0; i < mem->num_regions; i++) {
        free(mem->regions[i].data);
    }
    free(mem);
}

static WGMemRegion *find_region(WGMemorySpace *mem, uint64_t addr) {
    for (int i = 0; i < mem->num_regions; i++) {
        WGMemRegion *r = &mem->regions[i];
        if (addr >= r->base && addr < r->base + r->size) {
            return r;
        }
    }
    return NULL;
}

bool wg_memory_map(WGMemorySpace *mem, uint64_t base, uint64_t size, uint32_t prot) {
    if (mem->num_regions >= WG_MAX_REGIONS) {
        WG_LOGE(TAG, "Max regions exceeded");
        return false;
    }

    uint64_t aligned_size = (size + WG_PAGE_SIZE - 1) & ~(WG_PAGE_SIZE - 1);
    if (aligned_size == 0) aligned_size = WG_PAGE_SIZE;

    uint8_t *data = calloc(1, aligned_size);
    if (!data) {
        WG_LOGE(TAG, "Failed to allocate %llu bytes", (unsigned long long)aligned_size);
        return false;
    }

    WGMemRegion *r = &mem->regions[mem->num_regions++];
    r->base = base;
    r->size = aligned_size;
    r->prot = prot;
    r->data = data;

    return true;
}

bool wg_memory_unmap(WGMemorySpace *mem, uint64_t base) {
    for (int i = 0; i < mem->num_regions; i++) {
        if (mem->regions[i].base == base) {
            free(mem->regions[i].data);
            mem->regions[i] = mem->regions[--mem->num_regions];
            return true;
        }
    }
    return false;
}

bool wg_memory_protect(WGMemorySpace *mem, uint64_t base, uint64_t size, uint32_t prot) {
    WGMemRegion *r = find_region(mem, base);
    if (r) {
        r->prot = prot;
        return true;
    }
    return false;
}

static inline uint8_t *resolve(WGMemorySpace *mem, uint64_t addr) {
    WGMemRegion *r = find_region(mem, addr);
    if (!r) return NULL;
    return r->data + (addr - r->base);
}

uint8_t wg_memory_read_u8(WGMemorySpace *mem, uint64_t addr) {
    uint8_t *p = resolve(mem, addr);
    return p ? *p : 0;
}

uint16_t wg_memory_read_u16(WGMemorySpace *mem, uint64_t addr) {
    uint8_t *p = resolve(mem, addr);
    if (!p) return 0;
    uint16_t v;
    memcpy(&v, p, 2);
    return v;
}

uint32_t wg_memory_read_u32(WGMemorySpace *mem, uint64_t addr) {
    uint8_t *p = resolve(mem, addr);
    if (!p) return 0;
    uint32_t v;
    memcpy(&v, p, 4);
    return v;
}

uint64_t wg_memory_read_u64(WGMemorySpace *mem, uint64_t addr) {
    uint8_t *p = resolve(mem, addr);
    if (!p) return 0;
    uint64_t v;
    memcpy(&v, p, 8);
    return v;
}

void wg_memory_write_u8(WGMemorySpace *mem, uint64_t addr, uint8_t val) {
    uint8_t *p = resolve(mem, addr);
    if (p) *p = val;
}

void wg_memory_write_u16(WGMemorySpace *mem, uint64_t addr, uint16_t val) {
    uint8_t *p = resolve(mem, addr);
    if (p) memcpy(p, &val, 2);
}

void wg_memory_write_u32(WGMemorySpace *mem, uint64_t addr, uint32_t val) {
    uint8_t *p = resolve(mem, addr);
    if (p) memcpy(p, &val, 4);
}

void wg_memory_write_u64(WGMemorySpace *mem, uint64_t addr, uint64_t val) {
    uint8_t *p = resolve(mem, addr);
    if (p) memcpy(p, &val, 8);
}

bool wg_memory_read(WGMemorySpace *mem, uint64_t addr, void *buf, size_t len) {
    uint8_t *dst = buf;
    for (size_t i = 0; i < len; i++) {
        uint8_t *p = resolve(mem, addr + i);
        if (!p) return false;
        dst[i] = *p;
    }
    return true;
}

bool wg_memory_write(WGMemorySpace *mem, uint64_t addr, const void *buf, size_t len) {
    const uint8_t *src = buf;
    for (size_t i = 0; i < len; i++) {
        uint8_t *p = resolve(mem, addr + i);
        if (!p) return false;
        *p = src[i];
    }
    return true;
}
