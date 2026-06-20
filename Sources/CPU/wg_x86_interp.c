#include "wg_x86_interp.h"
#include "wg_x86_decode.h"
#include "wg_log.h"
#include <string.h>

#define TAG "Interp"

static uint64_t mask_for(int bytes) {
    if (bytes >= 8) return ~0ULL;
    return (1ULL << (bytes * 8)) - 1;
}

static int64_t sign_extend(uint64_t val, int bytes) {
    int bits = bytes * 8;
    uint64_t sign = 1ULL << (bits - 1);
    if (val & sign) {
        return (int64_t)(val | ~((1ULL << bits) - 1));
    }
    return (int64_t)val;
}

static uint64_t read_operand(WGx86State *cpu, WGMemorySpace *mem, const WGOperand *op) {
    uint64_t m = mask_for(op->size);
    switch (op->type) {
    case WG_OPERAND_REG:
        return cpu->gpr[op->reg_index] & m;
    case WG_OPERAND_IMM:
    case WG_OPERAND_REL:
        return (uint64_t)op->imm & m;
    case WG_OPERAND_MEM: {
        uint64_t addr = 0;
        if (op->mem_base == -2) {
            addr = (uint64_t)op->mem_disp;
        } else {
            if (op->mem_base >= 0) addr += cpu->gpr[op->mem_base];
            if (op->mem_index >= 0) addr += cpu->gpr[op->mem_index] * op->mem_scale;
            addr += op->mem_disp;
        }
        switch (op->size) {
            case 1: return wg_memory_read_u8(mem, addr);
            case 2: return wg_memory_read_u16(mem, addr);
            case 4: return wg_memory_read_u32(mem, addr);
            case 8: return wg_memory_read_u64(mem, addr);
            default: return 0;
        }
    }
    default:
        return 0;
    }
}

static void write_operand(WGx86State *cpu, WGMemorySpace *mem, const WGOperand *op, uint64_t val) {
    uint64_t m = mask_for(op->size);
    switch (op->type) {
    case WG_OPERAND_REG:
        if (op->size == 4) {
            // 32-bit writes zero-extend to 64 bits in x86-64
            cpu->gpr[op->reg_index] = val & 0xFFFFFFFF;
        } else if (op->size < 4) {
            uint64_t old = cpu->gpr[op->reg_index];
            cpu->gpr[op->reg_index] = (old & ~m) | (val & m);
        } else {
            cpu->gpr[op->reg_index] = val;
        }
        break;
    case WG_OPERAND_MEM: {
        uint64_t addr = 0;
        if (op->mem_base == -2) {
            addr = (uint64_t)op->mem_disp;
        } else {
            if (op->mem_base >= 0) addr += cpu->gpr[op->mem_base];
            if (op->mem_index >= 0) addr += cpu->gpr[op->mem_index] * op->mem_scale;
            addr += op->mem_disp;
        }
        switch (op->size) {
            case 1: wg_memory_write_u8(mem, addr, (uint8_t)val); break;
            case 2: wg_memory_write_u16(mem, addr, (uint16_t)val); break;
            case 4: wg_memory_write_u32(mem, addr, (uint32_t)val); break;
            case 8: wg_memory_write_u64(mem, addr, val); break;
        }
        break;
    }
    default:
        break;
    }
}

static uint64_t compute_ea(WGx86State *cpu, const WGOperand *op) {
    if (op->type != WG_OPERAND_MEM) return 0;
    uint64_t addr = 0;
    if (op->mem_base == -2) {
        addr = (uint64_t)op->mem_disp;
    } else {
        if (op->mem_base >= 0) addr += cpu->gpr[op->mem_base];
        if (op->mem_index >= 0) addr += cpu->gpr[op->mem_index] * op->mem_scale;
        addr += op->mem_disp;
    }
    return addr;
}

static bool eval_condition(WGx86State *cpu, uint8_t cc) {
    bool cf = wg_x86_get_flag(cpu, WG_FLAG_CF);
    bool zf = wg_x86_get_flag(cpu, WG_FLAG_ZF);
    bool sf = wg_x86_get_flag(cpu, WG_FLAG_SF);
    bool of = wg_x86_get_flag(cpu, WG_FLAG_OF);
    bool pf = wg_x86_get_flag(cpu, WG_FLAG_PF);

    switch (cc & 0xF) {
        case 0x0: return of;              // O
        case 0x1: return !of;             // NO
        case 0x2: return cf;              // B/C/NAE
        case 0x3: return !cf;             // NB/AE/NC
        case 0x4: return zf;              // E/Z
        case 0x5: return !zf;             // NE/NZ
        case 0x6: return cf || zf;        // BE/NA
        case 0x7: return !cf && !zf;      // A/NBE
        case 0x8: return sf;              // S
        case 0x9: return !sf;             // NS
        case 0xA: return pf;              // P/PE
        case 0xB: return !pf;             // NP/PO
        case 0xC: return sf != of;        // L/NGE
        case 0xD: return sf == of;        // GE/NL
        case 0xE: return zf || (sf!=of);  // LE/NG
        case 0xF: return !zf && (sf==of); // G/NLE
    }
    return false;
}

static void push64(WGx86State *cpu, WGMemorySpace *mem, uint64_t val) {
    cpu->gpr[WG_REG_RSP] -= 8;
    wg_memory_write_u64(mem, cpu->gpr[WG_REG_RSP], val);
}

static uint64_t pop64(WGx86State *cpu, WGMemorySpace *mem) {
    uint64_t val = wg_memory_read_u64(mem, cpu->gpr[WG_REG_RSP]);
    cpu->gpr[WG_REG_RSP] += 8;
    return val;
}

WGInterpResult wg_x86_exec_one(WGx86State *cpu, WGMemorySpace *mem) {
    uint8_t buf[16];
    for (int i = 0; i < 16; i++) {
        buf[i] = wg_memory_read_u8(mem, cpu->rip + i);
    }

    WGInstruction insn;
    int len = wg_x86_decode(buf, 16, cpu->rip, &insn);
    if (len == 0) {
        WG_LOGE(TAG, "Decode failed at RIP=0x%llx", (unsigned long long)cpu->rip);
        return WG_INTERP_ERROR;
    }

    uint64_t next_rip = cpu->rip + len;
    cpu->instruction_count++;

    switch (insn.opcode) {
    case WG_OP_NOP:
        break;

    case WG_OP_MOV: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[1]);
        write_operand(cpu, mem, &insn.operands[0], val);
        break;
    }

    case WG_OP_MOVZX: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[1]);
        write_operand(cpu, mem, &insn.operands[0], val);
        break;
    }

    case WG_OP_MOVSX: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[1]);
        int64_t sval = sign_extend(val, insn.operands[1].size);
        write_operand(cpu, mem, &insn.operands[0], (uint64_t)sval);
        break;
    }

    case WG_OP_LEA: {
        uint64_t ea = compute_ea(cpu, &insn.operands[1]);
        write_operand(cpu, mem, &insn.operands[0], ea);
        break;
    }

    case WG_OP_XCHG: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        write_operand(cpu, mem, &insn.operands[0], b);
        write_operand(cpu, mem, &insn.operands[1], a);
        break;
    }

    case WG_OP_PUSH: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        push64(cpu, mem, val);
        break;
    }

    case WG_OP_POP: {
        uint64_t val = pop64(cpu, mem);
        write_operand(cpu, mem, &insn.operands[0], val);
        break;
    }

    case WG_OP_ADD: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a + b;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_add(cpu, a, b, r, insn.op_size * 8);
        break;
    }

    case WG_OP_SUB: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a - b;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_sub(cpu, a, b, r, insn.op_size * 8);
        break;
    }

    case WG_OP_CMP: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a - b;
        wg_x86_update_flags_sub(cpu, a, b, r, insn.op_size * 8);
        break;
    }

    case WG_OP_AND: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a & b;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
        break;
    }

    case WG_OP_OR: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a | b;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
        break;
    }

    case WG_OP_XOR: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        if (insn.operands[1].size < insn.operands[0].size) {
            b = (uint64_t)sign_extend(b, insn.operands[1].size);
        }
        uint64_t r = a ^ b;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
        break;
    }

    case WG_OP_NOT: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        write_operand(cpu, mem, &insn.operands[0], ~val);
        break;
    }

    case WG_OP_NEG: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t r = (~val) + 1;
        write_operand(cpu, mem, &insn.operands[0], r);
        wg_x86_update_flags_sub(cpu, 0, val, r, insn.op_size * 8);
        break;
    }

    case WG_OP_INC: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t r = val + 1;
        write_operand(cpu, mem, &insn.operands[0], r);
        bool old_cf = wg_x86_get_flag(cpu, WG_FLAG_CF);
        wg_x86_update_flags_add(cpu, val, 1, r, insn.op_size * 8);
        wg_x86_set_flag(cpu, WG_FLAG_CF, old_cf); // INC doesn't affect CF
        break;
    }

    case WG_OP_DEC: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t r = val - 1;
        write_operand(cpu, mem, &insn.operands[0], r);
        bool old_cf = wg_x86_get_flag(cpu, WG_FLAG_CF);
        wg_x86_update_flags_sub(cpu, val, 1, r, insn.op_size * 8);
        wg_x86_set_flag(cpu, WG_FLAG_CF, old_cf);
        break;
    }

    case WG_OP_TEST: {
        uint64_t a = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t b = read_operand(cpu, mem, &insn.operands[1]);
        uint64_t r = a & b;
        wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
        break;
    }

    case WG_OP_SHL: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t count = read_operand(cpu, mem, &insn.operands[1]) & 0x3F;
        if (count > 0) {
            uint64_t r = val << count;
            write_operand(cpu, mem, &insn.operands[0], r);
            wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
            int bits = insn.op_size * 8;
            wg_x86_set_flag(cpu, WG_FLAG_CF, (val >> (bits - count)) & 1);
        }
        break;
    }

    case WG_OP_SHR: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t count = read_operand(cpu, mem, &insn.operands[1]) & 0x3F;
        if (count > 0) {
            uint64_t m = mask_for(insn.op_size);
            uint64_t r = (val & m) >> count;
            write_operand(cpu, mem, &insn.operands[0], r);
            wg_x86_update_flags_logic(cpu, r, insn.op_size * 8);
            wg_x86_set_flag(cpu, WG_FLAG_CF, (val >> (count - 1)) & 1);
        }
        break;
    }

    case WG_OP_SAR: {
        uint64_t val = read_operand(cpu, mem, &insn.operands[0]);
        uint64_t count = read_operand(cpu, mem, &insn.operands[1]) & 0x3F;
        if (count > 0) {
            int64_t sval = sign_extend(val, insn.op_size);
            int64_t r = sval >> count;
            write_operand(cpu, mem, &insn.operands[0], (uint64_t)r);
            wg_x86_update_flags_logic(cpu, (uint64_t)r, insn.op_size * 8);
            wg_x86_set_flag(cpu, WG_FLAG_CF, (val >> (count - 1)) & 1);
        }
        break;
    }

    case WG_OP_IMUL: {
        if (insn.num_operands == 1) {
            int64_t a = sign_extend(cpu->gpr[WG_REG_RAX], insn.op_size);
            int64_t b = sign_extend(read_operand(cpu, mem, &insn.operands[0]), insn.op_size);
            __int128 r = (__int128)a * b;
            cpu->gpr[WG_REG_RAX] = (uint64_t)r & mask_for(insn.op_size);
            cpu->gpr[WG_REG_RDX] = (uint64_t)(r >> (insn.op_size * 8)) & mask_for(insn.op_size);
        } else if (insn.num_operands == 2) {
            int64_t a = sign_extend(read_operand(cpu, mem, &insn.operands[0]), insn.op_size);
            int64_t b = sign_extend(read_operand(cpu, mem, &insn.operands[1]), insn.op_size);
            int64_t r = a * b;
            write_operand(cpu, mem, &insn.operands[0], (uint64_t)r);
        } else {
            int64_t b = sign_extend(read_operand(cpu, mem, &insn.operands[1]), insn.op_size);
            int64_t imm = sign_extend(read_operand(cpu, mem, &insn.operands[2]), insn.op_size);
            int64_t r = b * imm;
            write_operand(cpu, mem, &insn.operands[0], (uint64_t)r);
        }
        break;
    }

    case WG_OP_JMP:
        if (insn.operands[0].type == WG_OPERAND_REL) {
            next_rip = (uint64_t)insn.operands[0].imm;
        } else {
            next_rip = read_operand(cpu, mem, &insn.operands[0]);
        }
        break;

    case WG_OP_JCC:
        if (eval_condition(cpu, insn.condition)) {
            next_rip = (uint64_t)insn.operands[0].imm;
        }
        break;

    case WG_OP_CALL:
        push64(cpu, mem, next_rip);
        if (insn.operands[0].type == WG_OPERAND_REL) {
            next_rip = (uint64_t)insn.operands[0].imm;
        } else {
            next_rip = read_operand(cpu, mem, &insn.operands[0]);
        }
        // Check if this is a call to a Win32 stub (address in our thunk range)
        if (next_rip >= 0xDEAD0000 && next_rip < 0xDEAF0000) {
            // Win32 API stub — pop return address and signal
            next_rip = pop64(cpu, mem);
            cpu->rip = next_rip;
            return WG_INTERP_SYSCALL;
        }
        break;

    case WG_OP_RET: {
        next_rip = pop64(cpu, mem);
        if (insn.num_operands > 0) {
            cpu->gpr[WG_REG_RSP] += (uint64_t)insn.operands[0].imm;
        }
        if (next_rip == 0) {
            cpu->rip = next_rip;
            return WG_INTERP_HALT;
        }
        break;
    }

    case WG_OP_LEAVE:
        cpu->gpr[WG_REG_RSP] = cpu->gpr[WG_REG_RBP];
        cpu->gpr[WG_REG_RBP] = pop64(cpu, mem);
        break;

    case WG_OP_CMOVCC: {
        if (eval_condition(cpu, insn.condition)) {
            uint64_t val = read_operand(cpu, mem, &insn.operands[1]);
            write_operand(cpu, mem, &insn.operands[0], val);
        }
        break;
    }

    case WG_OP_SETCC: {
        bool cond = eval_condition(cpu, insn.condition);
        write_operand(cpu, mem, &insn.operands[0], cond ? 1 : 0);
        break;
    }

    case WG_OP_CDQ:
        if ((int32_t)cpu->gpr[WG_REG_RAX] < 0)
            cpu->gpr[WG_REG_RDX] = (cpu->gpr[WG_REG_RDX] & ~0xFFFFFFFFULL) | 0xFFFFFFFF;
        else
            cpu->gpr[WG_REG_RDX] &= ~0xFFFFFFFFULL;
        break;

    case WG_OP_CQO:
        cpu->gpr[WG_REG_RDX] = ((int64_t)cpu->gpr[WG_REG_RAX] < 0) ? ~0ULL : 0;
        break;

    case WG_OP_CDQE:
        cpu->gpr[WG_REG_RAX] = (uint64_t)(int64_t)(int32_t)(cpu->gpr[WG_REG_RAX] & 0xFFFFFFFF);
        break;

    case WG_OP_CWDE:
        cpu->gpr[WG_REG_RAX] = (cpu->gpr[WG_REG_RAX] & ~0xFFFFFFFFULL) |
                                (uint32_t)(int32_t)(int16_t)(cpu->gpr[WG_REG_RAX] & 0xFFFF);
        break;

    case WG_OP_BSWAP: {
        uint64_t val = cpu->gpr[insn.operands[0].reg_index];
        if (insn.op_size == 8) {
            val = __builtin_bswap64(val);
        } else {
            val = __builtin_bswap32((uint32_t)val);
        }
        cpu->gpr[insn.operands[0].reg_index] = val;
        break;
    }

    case WG_OP_CPUID:
        // Minimal CPUID emulation
        switch ((uint32_t)cpu->gpr[WG_REG_RAX]) {
            case 0:
                cpu->gpr[WG_REG_RAX] = 0x16;
                cpu->gpr[WG_REG_RBX] = 0x656E6957; // "Wine"
                cpu->gpr[WG_REG_RDX] = 0x73616C47; // "Glas"
                cpu->gpr[WG_REG_RCX] = 0x00007373; // "ss\0\0"
                break;
            case 1:
                cpu->gpr[WG_REG_RAX] = 0x000906EA; // fake family/model/stepping
                cpu->gpr[WG_REG_RBX] = 0x00100800;
                cpu->gpr[WG_REG_RCX] = 0x7FFAFBBF; // SSE4.2, POPCNT, etc.
                cpu->gpr[WG_REG_RDX] = 0xBFEBFBFF; // SSE, SSE2, etc.
                break;
            default:
                cpu->gpr[WG_REG_RAX] = 0;
                cpu->gpr[WG_REG_RBX] = 0;
                cpu->gpr[WG_REG_RCX] = 0;
                cpu->gpr[WG_REG_RDX] = 0;
                break;
        }
        break;

    case WG_OP_XORPS: {
        int dst = insn.operands[0].reg_index;
        int src = insn.operands[1].reg_index;
        if (insn.operands[1].type == WG_OPERAND_REG) {
            cpu->xmm[dst][0] ^= cpu->xmm[src][0];
            cpu->xmm[dst][1] ^= cpu->xmm[src][1];
        }
        break;
    }

    case WG_OP_CLC: wg_x86_set_flag(cpu, WG_FLAG_CF, false); break;
    case WG_OP_STC: wg_x86_set_flag(cpu, WG_FLAG_CF, true); break;
    case WG_OP_CMC: wg_x86_set_flag(cpu, WG_FLAG_CF, !wg_x86_get_flag(cpu, WG_FLAG_CF)); break;
    case WG_OP_CLD: wg_x86_set_flag(cpu, WG_FLAG_DF, false); break;
    case WG_OP_STD: wg_x86_set_flag(cpu, WG_FLAG_DF, true); break;

    case WG_OP_HLT:
        cpu->rip = next_rip;
        return WG_INTERP_HALT;

    case WG_OP_SYSCALL:
        cpu->rip = next_rip;
        return WG_INTERP_SYSCALL;

    case WG_OP_INT:
        cpu->rip = next_rip;
        return WG_INTERP_SYSCALL;

    case WG_OP_UNKNOWN:
        WG_LOGE(TAG, "Unknown opcode at RIP=0x%llx: %02x %02x %02x %02x",
                (unsigned long long)cpu->rip, buf[0], buf[1], buf[2], buf[3]);
        return WG_INTERP_ERROR;

    default:
        WG_LOGW(TAG, "Unimplemented: %s at RIP=0x%llx", wg_opcode_name(insn.opcode),
                (unsigned long long)cpu->rip);
        break;
    }

    cpu->rip = next_rip;
    return WG_INTERP_OK;
}

WGInterpResult wg_x86_exec_block(WGx86State *cpu, WGMemorySpace *mem, int max_insns) {
    for (int i = 0; i < max_insns; i++) {
        WGInterpResult r = wg_x86_exec_one(cpu, mem);
        if (r != WG_INTERP_OK) return r;
    }
    return WG_INTERP_OK;
}
