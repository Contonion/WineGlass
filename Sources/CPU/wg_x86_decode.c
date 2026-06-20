#include "wg_x86_decode.h"
#include <string.h>

// ModR/M byte helpers
#define MODRM_MOD(b)  (((b) >> 6) & 3)
#define MODRM_REG(b)  (((b) >> 3) & 7)
#define MODRM_RM(b)   ((b) & 7)

// SIB byte helpers
#define SIB_SCALE(b) (((b) >> 6) & 3)
#define SIB_INDEX(b) (((b) >> 3) & 7)
#define SIB_BASE(b)  ((b) & 7)

typedef struct {
    const uint8_t *start;
    const uint8_t *ptr;
    const uint8_t *end;
    uint64_t       rip;

    // Prefix state
    bool rex_present;
    int  rex_w;
    int  rex_r;
    int  rex_x;
    int  rex_b;
    bool has_66;
    bool has_67;
    bool has_f2;
    bool has_f3;
    bool has_lock;
    int  seg_override;
} DecodeCtx;

static uint8_t fetch8(DecodeCtx *c) {
    if (c->ptr >= c->end) return 0;
    return *c->ptr++;
}

static uint16_t fetch16(DecodeCtx *c) {
    uint16_t v = 0;
    if (c->ptr + 2 <= c->end) {
        v = c->ptr[0] | ((uint16_t)c->ptr[1] << 8);
        c->ptr += 2;
    }
    return v;
}

static uint32_t fetch32(DecodeCtx *c) {
    uint32_t v = 0;
    if (c->ptr + 4 <= c->end) {
        v = c->ptr[0] | ((uint32_t)c->ptr[1] << 8) |
            ((uint32_t)c->ptr[2] << 16) | ((uint32_t)c->ptr[3] << 24);
        c->ptr += 4;
    }
    return v;
}

static uint64_t fetch64(DecodeCtx *c) {
    uint64_t lo = fetch32(c);
    uint64_t hi = fetch32(c);
    return lo | (hi << 32);
}

static int32_t fetch_simm32(DecodeCtx *c) {
    return (int32_t)fetch32(c);
}

static int effective_op_size(DecodeCtx *c) {
    if (c->rex_w) return 8;
    if (c->has_66) return 2;
    return 4;
}

static void decode_modrm_mem(DecodeCtx *c, WGOperand *op, int addr_size) {
    uint8_t modrm = fetch8(c);
    int mod = MODRM_MOD(modrm);
    int rm  = MODRM_RM(modrm) | (c->rex_b << 3);
    int reg = MODRM_REG(modrm) | (c->rex_r << 3);

    // Reg operand in bits 3-5 is set on the parent; we fill mem here

    (void)reg; // caller uses this separately

    if (mod == 3) {
        op->type = WG_OPERAND_REG;
        op->reg_index = rm;
        return;
    }

    op->type = WG_OPERAND_MEM;
    op->mem_base = -1;
    op->mem_index = -1;
    op->mem_scale = 1;
    op->mem_disp = 0;
    op->mem_seg = c->seg_override;

    int base_rm = MODRM_RM(modrm); // without REX.B for SIB check

    if (base_rm == 4) {
        // SIB byte follows
        uint8_t sib = fetch8(c);
        int sib_base  = SIB_BASE(sib) | (c->rex_b << 3);
        int sib_index = SIB_INDEX(sib) | (c->rex_x << 3);
        int sib_scale = 1 << SIB_SCALE(sib);

        if (sib_index != 4) { // index=4(RSP) means no index
            op->mem_index = sib_index;
            op->mem_scale = sib_scale;
        }

        if (mod == 0 && SIB_BASE(sib) == 5) {
            op->mem_disp = fetch_simm32(c);
            // RIP-relative or absolute depending on index
            if (op->mem_index == -1) {
                op->mem_base = -1; // absolute
            }
        } else {
            op->mem_base = sib_base;
        }
    } else if (mod == 0 && base_rm == 5) {
        // RIP-relative
        int32_t disp = fetch_simm32(c);
        op->mem_base = -2; // sentinel for RIP-relative
        op->mem_disp = (int64_t)(c->rip + (c->ptr - c->start)) + disp;
    } else {
        op->mem_base = MODRM_RM(modrm) | (c->rex_b << 3);
    }

    if (mod == 1) {
        op->mem_disp = (int8_t)fetch8(c);
    } else if (mod == 2) {
        op->mem_disp = fetch_simm32(c);
    }
}

// Returns the reg field from ModR/M (with REX.R applied)
static int decode_modrm(DecodeCtx *c, WGOperand *rm_op, WGOperand *reg_op, int op_size) {
    const uint8_t *before = c->ptr;
    uint8_t modrm = *c->ptr; // peek, don't consume — decode_modrm_mem consumes it

    int reg = MODRM_REG(modrm) | (c->rex_r << 3);

    rm_op->size = op_size;
    decode_modrm_mem(c, rm_op, 8);

    if (reg_op) {
        reg_op->type = WG_OPERAND_REG;
        reg_op->reg_index = reg;
        reg_op->size = op_size;
    }

    return reg;
}

int wg_x86_decode(const uint8_t *code, int max_len, uint64_t rip, WGInstruction *out) {
    memset(out, 0, sizeof(*out));
    out->segment_override = -1;

    if (max_len <= 0) return 0;

    DecodeCtx ctx = {
        .start = code,
        .ptr = code,
        .end = code + max_len,
        .rip = rip,
        .seg_override = -1,
    };
    DecodeCtx *c = &ctx;

    // Parse prefixes
    bool parsing_prefixes = true;
    while (parsing_prefixes && c->ptr < c->end) {
        uint8_t b = *c->ptr;
        switch (b) {
            case 0xF0: c->has_lock = true; c->ptr++; break;
            case 0xF2: c->has_f2 = true; c->ptr++; break;
            case 0xF3: c->has_f3 = true; c->ptr++; break;
            case 0x66: c->has_66 = true; c->ptr++; break;
            case 0x67: c->has_67 = true; c->ptr++; break;
            case 0x26: c->seg_override = 0; c->ptr++; break; // ES
            case 0x2E: c->seg_override = 1; c->ptr++; break; // CS
            case 0x36: c->seg_override = 2; c->ptr++; break; // SS
            case 0x3E: c->seg_override = 3; c->ptr++; break; // DS
            case 0x64: c->seg_override = 4; c->ptr++; break; // FS
            case 0x65: c->seg_override = 5; c->ptr++; break; // GS
            default:
                if (b >= 0x40 && b <= 0x4F) {
                    c->rex_present = true;
                    c->rex_w = (b >> 3) & 1;
                    c->rex_r = (b >> 2) & 1;
                    c->rex_x = (b >> 1) & 1;
                    c->rex_b = b & 1;
                    c->ptr++;
                } else {
                    parsing_prefixes = false;
                }
                break;
        }
    }

    out->has_lock = c->has_lock;
    out->has_rep = c->has_f3;
    out->has_repne = c->has_f2;
    out->segment_override = c->seg_override;
    out->addr_size = c->has_67 ? 4 : 8;

    if (c->ptr >= c->end) return 0;

    int op_sz = effective_op_size(c);
    out->op_size = op_sz;

    uint8_t opcode = fetch8(c);

    switch (opcode) {
    // NOP
    case 0x90:
        if (!c->rex_present) {
            out->opcode = WG_OP_NOP;
        } else {
            // XCHG RAX, RAX (with REX.W) = NOP; XCHG R8, RAX otherwise
            out->opcode = WG_OP_XCHG;
            out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0|c->rex_b, .size=op_sz};
            out->operands[1] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=op_sz};
            out->num_operands = 2;
        }
        break;

    // MOV r/m, r  (88, 89)
    case 0x88: case 0x89: {
        int sz = (opcode == 0x88) ? 1 : op_sz;
        out->opcode = WG_OP_MOV;
        decode_modrm(c, &out->operands[0], &out->operands[1], sz);
        out->num_operands = 2;
        break;
    }
    // MOV r, r/m  (8A, 8B)
    case 0x8A: case 0x8B: {
        int sz = (opcode == 0x8A) ? 1 : op_sz;
        out->opcode = WG_OP_MOV;
        decode_modrm(c, &out->operands[1], &out->operands[0], sz);
        out->num_operands = 2;
        break;
    }
    // MOV r, imm (B0-BF)
    case 0xB0: case 0xB1: case 0xB2: case 0xB3:
    case 0xB4: case 0xB5: case 0xB6: case 0xB7: {
        out->opcode = WG_OP_MOV;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=(opcode-0xB0)|(c->rex_b<<3), .size=1};
        out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch8(c), .size=1};
        out->num_operands = 2;
        break;
    }
    case 0xB8: case 0xB9: case 0xBA: case 0xBB:
    case 0xBC: case 0xBD: case 0xBE: case 0xBF: {
        out->opcode = WG_OP_MOV;
        int reg = (opcode - 0xB8) | (c->rex_b << 3);
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=reg, .size=op_sz};
        if (c->rex_w) {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int64_t)fetch64(c), .size=8};
        } else {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int64_t)(int32_t)fetch32(c), .size=op_sz};
        }
        out->num_operands = 2;
        break;
    }
    // MOV r/m, imm (C6, C7)
    case 0xC6: case 0xC7: {
        int sz = (opcode == 0xC6) ? 1 : op_sz;
        out->opcode = WG_OP_MOV;
        decode_modrm(c, &out->operands[0], NULL, sz);
        if (sz == 1) out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=1};
        else         out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=sz};
        out->num_operands = 2;
        break;
    }

    // ADD/OR/ADC/SBB/AND/SUB/XOR/CMP r/m, imm8 (group 80-83)
    case 0x80: case 0x81: case 0x82: case 0x83: {
        int sz = (opcode == 0x80 || opcode == 0x82) ? 1 : op_sz;
        WGOperand reg_op;
        decode_modrm(c, &out->operands[0], &reg_op, sz);
        int grp = reg_op.reg_index & 7;
        WGOpcode ops[] = {WG_OP_ADD, WG_OP_OR, WG_OP_ADC, WG_OP_SBB,
                          WG_OP_AND, WG_OP_SUB, WG_OP_XOR, WG_OP_CMP};
        out->opcode = ops[grp];
        if (opcode == 0x83) {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=sz};
        } else if (sz == 1) {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=1};
        } else {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=sz};
        }
        out->num_operands = 2;
        break;
    }

    // ALU r/m, r (00-3D pattern: ADD, OR, ADC, SBB, AND, SUB, XOR, CMP)
    case 0x00: case 0x01: case 0x02: case 0x03: case 0x04: case 0x05:
    case 0x08: case 0x09: case 0x0A: case 0x0B: case 0x0C: case 0x0D:
    case 0x10: case 0x11: case 0x12: case 0x13: case 0x14: case 0x15:
    case 0x18: case 0x19: case 0x1A: case 0x1B: case 0x1C: case 0x1D:
    case 0x20: case 0x21: case 0x22: case 0x23: case 0x24: case 0x25:
    case 0x28: case 0x29: case 0x2A: case 0x2B: case 0x2C: case 0x2D:
    case 0x30: case 0x31: case 0x32: case 0x33: case 0x34: case 0x35:
    case 0x38: case 0x39: case 0x3A: case 0x3B: case 0x3C: case 0x3D: {
        WGOpcode ops[] = {WG_OP_ADD, WG_OP_OR, WG_OP_ADC, WG_OP_SBB,
                          WG_OP_AND, WG_OP_SUB, WG_OP_XOR, WG_OP_CMP};
        int grp = (opcode >> 3) & 7;
        int sub = opcode & 7;
        out->opcode = ops[grp];

        if (sub <= 1) {
            int sz = (sub == 0) ? 1 : op_sz;
            decode_modrm(c, &out->operands[0], &out->operands[1], sz);
        } else if (sub <= 3) {
            int sz = (sub == 2) ? 1 : op_sz;
            decode_modrm(c, &out->operands[1], &out->operands[0], sz);
        } else if (sub == 4) {
            out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=1};
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=1};
        } else {
            out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=op_sz};
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=op_sz};
        }
        out->num_operands = 2;
        break;
    }

    // TEST r/m, r (84, 85)
    case 0x84: case 0x85: {
        int sz = (opcode == 0x84) ? 1 : op_sz;
        out->opcode = WG_OP_TEST;
        decode_modrm(c, &out->operands[0], &out->operands[1], sz);
        out->num_operands = 2;
        break;
    }
    // TEST AL/rAX, imm (A8, A9)
    case 0xA8: {
        out->opcode = WG_OP_TEST;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=1};
        out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch8(c), .size=1};
        out->num_operands = 2;
        break;
    }
    case 0xA9: {
        out->opcode = WG_OP_TEST;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=op_sz};
        out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=op_sz};
        out->num_operands = 2;
        break;
    }

    // PUSH r (50-57)
    case 0x50: case 0x51: case 0x52: case 0x53:
    case 0x54: case 0x55: case 0x56: case 0x57: {
        out->opcode = WG_OP_PUSH;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=(opcode-0x50)|(c->rex_b<<3), .size=8};
        out->num_operands = 1;
        break;
    }
    // POP r (58-5F)
    case 0x58: case 0x59: case 0x5A: case 0x5B:
    case 0x5C: case 0x5D: case 0x5E: case 0x5F: {
        out->opcode = WG_OP_POP;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=(opcode-0x58)|(c->rex_b<<3), .size=8};
        out->num_operands = 1;
        break;
    }
    // PUSH imm8 (6A)
    case 0x6A: {
        out->opcode = WG_OP_PUSH;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=8};
        out->num_operands = 1;
        break;
    }
    // PUSH imm32 (68)
    case 0x68: {
        out->opcode = WG_OP_PUSH;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=8};
        out->num_operands = 1;
        break;
    }

    // LEA r, m (8D)
    case 0x8D: {
        out->opcode = WG_OP_LEA;
        decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
        out->num_operands = 2;
        break;
    }

    // Jcc short (70-7F)
    case 0x70: case 0x71: case 0x72: case 0x73:
    case 0x74: case 0x75: case 0x76: case 0x77:
    case 0x78: case 0x79: case 0x7A: case 0x7B:
    case 0x7C: case 0x7D: case 0x7E: case 0x7F: {
        out->opcode = WG_OP_JCC;
        out->condition = opcode - 0x70;
        int8_t rel = (int8_t)fetch8(c);
        uint64_t target = rip + (c->ptr - c->start) + rel;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REL, .imm=(int64_t)target, .size=8};
        out->num_operands = 1;
        break;
    }

    // JMP rel8 (EB)
    case 0xEB: {
        out->opcode = WG_OP_JMP;
        int8_t rel = (int8_t)fetch8(c);
        uint64_t target = rip + (c->ptr - c->start) + rel;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REL, .imm=(int64_t)target, .size=8};
        out->num_operands = 1;
        break;
    }
    // JMP rel32 (E9)
    case 0xE9: {
        out->opcode = WG_OP_JMP;
        int32_t rel = fetch_simm32(c);
        uint64_t target = rip + (c->ptr - c->start) + rel;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REL, .imm=(int64_t)target, .size=8};
        out->num_operands = 1;
        break;
    }

    // CALL rel32 (E8)
    case 0xE8: {
        out->opcode = WG_OP_CALL;
        int32_t rel = fetch_simm32(c);
        uint64_t target = rip + (c->ptr - c->start) + rel;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REL, .imm=(int64_t)target, .size=8};
        out->num_operands = 1;
        break;
    }

    // RET (C3)
    case 0xC3: {
        out->opcode = WG_OP_RET;
        out->num_operands = 0;
        break;
    }
    // RET imm16 (C2)
    case 0xC2: {
        out->opcode = WG_OP_RET;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch16(c), .size=2};
        out->num_operands = 1;
        break;
    }

    // LEAVE (C9)
    case 0xC9: out->opcode = WG_OP_LEAVE; break;

    // Group FF: INC/DEC/CALL/JMP/PUSH r/m
    case 0xFF: {
        WGOperand reg_op;
        decode_modrm(c, &out->operands[0], &reg_op, op_sz);
        out->num_operands = 1;
        switch (reg_op.reg_index & 7) {
            case 0: out->opcode = WG_OP_INC; break;
            case 1: out->opcode = WG_OP_DEC; break;
            case 2: out->opcode = WG_OP_CALL; out->operands[0].size = 8; break;
            case 4: out->opcode = WG_OP_JMP; out->operands[0].size = 8; break;
            case 6: out->opcode = WG_OP_PUSH; out->operands[0].size = 8; break;
            default: out->opcode = WG_OP_UNKNOWN; break;
        }
        break;
    }

    // Group F6/F7: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV
    case 0xF6: case 0xF7: {
        int sz = (opcode == 0xF6) ? 1 : op_sz;
        WGOperand reg_op;
        decode_modrm(c, &out->operands[0], &reg_op, sz);
        switch (reg_op.reg_index & 7) {
            case 0: case 1:
                out->opcode = WG_OP_TEST;
                if (sz == 1) out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch8(c), .size=1};
                else         out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=sz};
                out->num_operands = 2;
                break;
            case 2: out->opcode = WG_OP_NOT; out->num_operands = 1; break;
            case 3: out->opcode = WG_OP_NEG; out->num_operands = 1; break;
            case 4: out->opcode = WG_OP_MUL; out->num_operands = 1; break;
            case 5: out->opcode = WG_OP_IMUL; out->num_operands = 1; break;
            case 6: out->opcode = WG_OP_DIV; out->num_operands = 1; break;
            case 7: out->opcode = WG_OP_IDIV; out->num_operands = 1; break;
        }
        break;
    }

    // Shift/rotate group (D0-D3, C0-C1)
    case 0xC0: case 0xC1: case 0xD0: case 0xD1: case 0xD2: case 0xD3: {
        int sz = (opcode == 0xC0 || opcode == 0xD0 || opcode == 0xD2) ? 1 : op_sz;
        WGOperand reg_op;
        decode_modrm(c, &out->operands[0], &reg_op, sz);

        WGOpcode shift_ops[] = {WG_OP_ROL, WG_OP_ROR, WG_OP_UNKNOWN, WG_OP_UNKNOWN,
                                WG_OP_SHL, WG_OP_SHR, WG_OP_SHL, WG_OP_SAR};
        out->opcode = shift_ops[reg_op.reg_index & 7];

        if (opcode == 0xC0 || opcode == 0xC1) {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch8(c), .size=1};
        } else if (opcode == 0xD0 || opcode == 0xD1) {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_IMM, .imm=1, .size=1};
        } else {
            out->operands[1] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=1, .size=1}; // CL
        }
        out->num_operands = 2;
        break;
    }

    // XCHG r, rAX (91-97)
    case 0x91: case 0x92: case 0x93: case 0x94:
    case 0x95: case 0x96: case 0x97: {
        out->opcode = WG_OP_XCHG;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=(opcode-0x90)|(c->rex_b<<3), .size=op_sz};
        out->operands[1] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=0, .size=op_sz};
        out->num_operands = 2;
        break;
    }

    // CBW/CWDE/CDQE (98), CWD/CDQ/CQO (99)
    case 0x98:
        if (c->rex_w)       out->opcode = WG_OP_CDQE;
        else if (c->has_66) out->opcode = WG_OP_CBW;
        else                out->opcode = WG_OP_CWDE;
        break;
    case 0x99:
        if (c->rex_w) out->opcode = WG_OP_CQO;
        else          out->opcode = WG_OP_CDQ;
        break;

    // INT (CD)
    case 0xCD: {
        out->opcode = WG_OP_INT;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch8(c), .size=1};
        out->num_operands = 1;
        break;
    }
    case 0xCC: {
        out->opcode = WG_OP_INT;
        out->operands[0] = (WGOperand){.type=WG_OPERAND_IMM, .imm=3, .size=1};
        out->num_operands = 1;
        break;
    }

    // HLT
    case 0xF4: out->opcode = WG_OP_HLT; break;

    // CLC, STC, CMC, CLD, STD
    case 0xF8: out->opcode = WG_OP_CLC; break;
    case 0xF9: out->opcode = WG_OP_STC; break;
    case 0xF5: out->opcode = WG_OP_CMC; break;
    case 0xFC: out->opcode = WG_OP_CLD; break;
    case 0xFD: out->opcode = WG_OP_STD; break;

    // String ops
    case 0xA4: out->opcode = WG_OP_MOVSB; break;
    case 0xA5: out->opcode = c->rex_w ? WG_OP_MOVSQ : (c->has_66 ? WG_OP_MOVSW : WG_OP_MOVSD_STR); break;
    case 0xAA: out->opcode = WG_OP_STOSB; break;
    case 0xAB: out->opcode = c->rex_w ? WG_OP_STOSQ : (c->has_66 ? WG_OP_STOSW : WG_OP_STOSD); break;

    // IMUL r, r/m (two-op, 0F AF handled below)
    case 0x69: case 0x6B: {
        out->opcode = WG_OP_IMUL;
        decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
        if (opcode == 0x6B) {
            out->operands[2] = (WGOperand){.type=WG_OPERAND_IMM, .imm=(int8_t)fetch8(c), .size=op_sz};
        } else {
            out->operands[2] = (WGOperand){.type=WG_OPERAND_IMM, .imm=fetch_simm32(c), .size=op_sz};
        }
        out->num_operands = 3;
        break;
    }

    // Two-byte opcodes (0F prefix)
    case 0x0F: {
        uint8_t op2 = fetch8(c);
        switch (op2) {
        // Jcc near (0F 80 - 0F 8F)
        case 0x80: case 0x81: case 0x82: case 0x83:
        case 0x84: case 0x85: case 0x86: case 0x87:
        case 0x88: case 0x89: case 0x8A: case 0x8B:
        case 0x8C: case 0x8D: case 0x8E: case 0x8F: {
            out->opcode = WG_OP_JCC;
            out->condition = op2 - 0x80;
            int32_t rel = fetch_simm32(c);
            uint64_t target = rip + (c->ptr - c->start) + rel;
            out->operands[0] = (WGOperand){.type=WG_OPERAND_REL, .imm=(int64_t)target, .size=8};
            out->num_operands = 1;
            break;
        }
        // SETcc (0F 90 - 0F 9F)
        case 0x90: case 0x91: case 0x92: case 0x93:
        case 0x94: case 0x95: case 0x96: case 0x97:
        case 0x98: case 0x99: case 0x9A: case 0x9B:
        case 0x9C: case 0x9D: case 0x9E: case 0x9F: {
            out->opcode = WG_OP_SETCC;
            out->condition = op2 - 0x90;
            decode_modrm(c, &out->operands[0], NULL, 1);
            out->num_operands = 1;
            break;
        }
        // CMOVcc (0F 40 - 0F 4F)
        case 0x40: case 0x41: case 0x42: case 0x43:
        case 0x44: case 0x45: case 0x46: case 0x47:
        case 0x48: case 0x49: case 0x4A: case 0x4B:
        case 0x4C: case 0x4D: case 0x4E: case 0x4F: {
            out->opcode = WG_OP_CMOVCC;
            out->condition = op2 - 0x40;
            decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
            out->num_operands = 2;
            break;
        }
        // MOVZX (0F B6, 0F B7)
        case 0xB6: case 0xB7: {
            out->opcode = WG_OP_MOVZX;
            int src_sz = (op2 == 0xB6) ? 1 : 2;
            decode_modrm(c, &out->operands[1], &out->operands[0], src_sz);
            out->operands[0].size = op_sz;
            out->num_operands = 2;
            break;
        }
        // MOVSX (0F BE, 0F BF)
        case 0xBE: case 0xBF: {
            out->opcode = WG_OP_MOVSX;
            int src_sz = (op2 == 0xBE) ? 1 : 2;
            decode_modrm(c, &out->operands[1], &out->operands[0], src_sz);
            out->operands[0].size = op_sz;
            out->num_operands = 2;
            break;
        }
        // IMUL r, r/m (0F AF)
        case 0xAF: {
            out->opcode = WG_OP_IMUL;
            decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
            out->num_operands = 2;
            break;
        }
        // CPUID
        case 0xA2: out->opcode = WG_OP_CPUID; break;
        // RDTSC
        case 0x31: out->opcode = WG_OP_RDTSC; break;
        // SYSCALL
        case 0x05: out->opcode = WG_OP_SYSCALL; break;
        // BSF/BSR
        case 0xBC: {
            out->opcode = WG_OP_BSF;
            decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
            out->num_operands = 2;
            break;
        }
        case 0xBD: {
            out->opcode = WG_OP_BSR;
            decode_modrm(c, &out->operands[1], &out->operands[0], op_sz);
            out->num_operands = 2;
            break;
        }
        // BSWAP (0F C8+rd)
        case 0xC8: case 0xC9: case 0xCA: case 0xCB:
        case 0xCC: case 0xCD: case 0xCE: case 0xCF: {
            out->opcode = WG_OP_BSWAP;
            out->operands[0] = (WGOperand){.type=WG_OPERAND_REG, .reg_index=(op2-0xC8)|(c->rex_b<<3), .size=op_sz};
            out->num_operands = 1;
            break;
        }
        // NOP (0F 1F /0 — multi-byte NOP)
        case 0x1F: {
            out->opcode = WG_OP_NOP;
            decode_modrm(c, &out->operands[0], NULL, op_sz);
            out->num_operands = 0;
            break;
        }
        // MOVUPS/MOVAPS (0F 10, 0F 11, 0F 28, 0F 29)
        case 0x10: case 0x11: {
            out->opcode = WG_OP_MOVUPS;
            if (op2 == 0x10) decode_modrm(c, &out->operands[1], &out->operands[0], 16);
            else             decode_modrm(c, &out->operands[0], &out->operands[1], 16);
            out->num_operands = 2;
            break;
        }
        case 0x28: case 0x29: {
            out->opcode = WG_OP_MOVAPS;
            if (op2 == 0x28) decode_modrm(c, &out->operands[1], &out->operands[0], 16);
            else             decode_modrm(c, &out->operands[0], &out->operands[1], 16);
            out->num_operands = 2;
            break;
        }
        // XORPS (0F 57)
        case 0x57: {
            out->opcode = WG_OP_XORPS;
            decode_modrm(c, &out->operands[1], &out->operands[0], 16);
            out->num_operands = 2;
            break;
        }

        default:
            out->opcode = WG_OP_UNKNOWN;
            break;
        }
        break;
    }

    default:
        out->opcode = WG_OP_UNKNOWN;
        break;
    }

    out->length = (int)(c->ptr - c->start);
    return out->length;
}

const char *wg_opcode_name(WGOpcode op) {
    static const char *names[] = {
        [WG_OP_UNKNOWN]="???", [WG_OP_NOP]="NOP",
        [WG_OP_MOV]="MOV", [WG_OP_MOVZX]="MOVZX", [WG_OP_MOVSX]="MOVSX",
        [WG_OP_LEA]="LEA", [WG_OP_XCHG]="XCHG",
        [WG_OP_PUSH]="PUSH", [WG_OP_POP]="POP",
        [WG_OP_ADD]="ADD", [WG_OP_SUB]="SUB", [WG_OP_ADC]="ADC", [WG_OP_SBB]="SBB",
        [WG_OP_AND]="AND", [WG_OP_OR]="OR", [WG_OP_XOR]="XOR",
        [WG_OP_NOT]="NOT", [WG_OP_NEG]="NEG",
        [WG_OP_INC]="INC", [WG_OP_DEC]="DEC",
        [WG_OP_CMP]="CMP", [WG_OP_TEST]="TEST",
        [WG_OP_SHL]="SHL", [WG_OP_SHR]="SHR", [WG_OP_SAR]="SAR",
        [WG_OP_ROL]="ROL", [WG_OP_ROR]="ROR",
        [WG_OP_IMUL]="IMUL", [WG_OP_MUL]="MUL", [WG_OP_IDIV]="IDIV", [WG_OP_DIV]="DIV",
        [WG_OP_JMP]="JMP", [WG_OP_JCC]="Jcc", [WG_OP_CALL]="CALL", [WG_OP_RET]="RET",
        [WG_OP_CMOVCC]="CMOVcc", [WG_OP_SETCC]="SETcc",
        [WG_OP_CQO]="CQO", [WG_OP_CDQ]="CDQ", [WG_OP_CBW]="CBW",
        [WG_OP_CWDE]="CWDE", [WG_OP_CDQE]="CDQE",
        [WG_OP_LEAVE]="LEAVE", [WG_OP_INT]="INT",
        [WG_OP_SYSCALL]="SYSCALL", [WG_OP_HLT]="HLT",
        [WG_OP_CPUID]="CPUID", [WG_OP_RDTSC]="RDTSC",
        [WG_OP_BSWAP]="BSWAP", [WG_OP_BSF]="BSF", [WG_OP_BSR]="BSR",
        [WG_OP_CLC]="CLC", [WG_OP_STC]="STC", [WG_OP_CMC]="CMC",
        [WG_OP_CLD]="CLD", [WG_OP_STD]="STD",
        [WG_OP_MOVAPS]="MOVAPS", [WG_OP_MOVUPS]="MOVUPS",
        [WG_OP_XORPS]="XORPS",
    };
    if (op < sizeof(names)/sizeof(names[0]) && names[op]) return names[op];
    return "???";
}
