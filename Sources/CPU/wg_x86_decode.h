#ifndef WG_X86_DECODE_H
#define WG_X86_DECODE_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    WG_OP_UNKNOWN = 0,
    WG_OP_NOP,
    WG_OP_MOV, WG_OP_MOVZX, WG_OP_MOVSX, WG_OP_LEA, WG_OP_XCHG,
    WG_OP_PUSH, WG_OP_POP,
    WG_OP_ADD, WG_OP_SUB, WG_OP_ADC, WG_OP_SBB,
    WG_OP_AND, WG_OP_OR, WG_OP_XOR, WG_OP_NOT, WG_OP_NEG,
    WG_OP_INC, WG_OP_DEC,
    WG_OP_CMP, WG_OP_TEST,
    WG_OP_SHL, WG_OP_SHR, WG_OP_SAR, WG_OP_ROL, WG_OP_ROR,
    WG_OP_IMUL, WG_OP_MUL, WG_OP_IDIV, WG_OP_DIV,
    WG_OP_JMP, WG_OP_JCC, WG_OP_CALL, WG_OP_RET,
    WG_OP_CMOVCC,
    WG_OP_SETCC,
    WG_OP_CQO, WG_OP_CDQ, WG_OP_CBW, WG_OP_CWDE, WG_OP_CDQE,
    WG_OP_MOVSB, WG_OP_MOVSW, WG_OP_MOVSD_STR, WG_OP_MOVSQ,
    WG_OP_STOSB, WG_OP_STOSW, WG_OP_STOSD, WG_OP_STOSQ,
    WG_OP_REP,
    WG_OP_LEAVE,
    WG_OP_INT, WG_OP_SYSCALL, WG_OP_HLT,
    WG_OP_CPUID,
    WG_OP_RDTSC,
    WG_OP_BSWAP,
    WG_OP_BSF, WG_OP_BSR,
    WG_OP_BT, WG_OP_BTS, WG_OP_BTR, WG_OP_BTC,
    WG_OP_MOVD_XMM, WG_OP_MOVQ_XMM,
    WG_OP_MOVAPS, WG_OP_MOVUPS,
    WG_OP_XORPS,
    WG_OP_CLC, WG_OP_STC, WG_OP_CMC,
    WG_OP_CLD, WG_OP_STD,
} WGOpcode;

typedef enum {
    WG_OPERAND_NONE = 0,
    WG_OPERAND_REG,
    WG_OPERAND_MEM,
    WG_OPERAND_IMM,
    WG_OPERAND_REL,
} WGOperandType;

typedef struct {
    WGOperandType type;
    int           size; // operand size in bytes (1, 2, 4, 8)

    // REG
    int reg_index; // 0-15

    // MEM: [base + index*scale + disp]
    int     mem_base;   // register index or -1
    int     mem_index;  // register index or -1
    int     mem_scale;  // 1, 2, 4, 8
    int64_t mem_disp;
    int     mem_seg;    // segment override or -1

    // IMM / REL
    int64_t imm;
} WGOperand;

typedef struct {
    WGOpcode  opcode;
    int       length;       // instruction length in bytes
    WGOperand operands[3];
    int       num_operands;

    // Prefix state
    int  op_size;           // effective operand size (1, 2, 4, 8)
    int  addr_size;         // effective address size (4, 8)
    bool has_lock;
    bool has_rep;
    bool has_repne;
    int  segment_override;  // -1 or segment register

    // For Jcc/CMOVcc/SETcc
    uint8_t condition;
} WGInstruction;

// Decode one instruction from the byte stream.
// Returns the number of bytes consumed, or 0 on failure.
int wg_x86_decode(const uint8_t *code, int max_len, uint64_t rip, WGInstruction *out);

const char *wg_opcode_name(WGOpcode op);

#endif
