/*
 * x86_codec.h - routines for encoding/decoding x86 instructions.
 */

#ifndef X86_CODEC_H
#define X86_CODEC_H

/* #include "x86_register.h" */
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Represents an x86 register. */
typedef uint16_t x86_reg_t;

/* Represents a memory address. */
typedef struct x86_mem_t
{
    x86_reg_t segment;
    x86_reg_t base;
    x86_reg_t index;
    uint16_t scaling;
    uint32_t displacement; 
} x86_mem_t;

/* Represents an immediate. */
typedef uint32_t x86_imm_t;

/* Represents a relative offset to EIP. */
typedef int32_t x86_rel_t;

/* Enumerated values for the type of an operand. */
enum x86_opr_type
{
    OPR_NONE    = 0,    /* the operand is not used */
    OPR_REG     = 1,    /* the operand refers to a register */
    OPR_MEM     = 2,    /* the operand refers to a memory location */
    OPR_IMM     = 3,    /* the operand is an immediate */
    OPR_REL     = 4     /* the operand is an (signed) offset to EIP */
};

/* Enumerated values for the size of an operand. */
enum x86_opr_size
{
    OPR_1BIT    = 0,
    OPR_2BIT    = 1,
    OPR_4BIT    = 2,
    OPR_8BIT    = 3,
    OPR_16BIT   = 4,
    OPR_32BIT   = 5,
    OPR_64BIT   = 6,
    OPR_128BIT  = 7,
    OPR_256BIT  = 8,
    OPR_80BIT   = 15    /* long double */
};

/* Represents an operand. */
typedef struct x86_opr_t
{
    unsigned char type; /* enum x86_opr_type */
    unsigned char size; /* enum x86_opr_size */
    union 
    {
        x86_reg_t reg;
        x86_mem_t mem;
        x86_imm_t imm;
        x86_rel_t rel;
    } val;              /* value */
} x86_opr_t;

#if 0

/**
 * Enumerated values for the type of a value accessible by an instruction.
 * The value may be stored in a register, in a memory location, or as an
 * immediate.
 */
enum x86_value_type
{
    VT_NONE = 0,       /* invalid */
    VT_I8   = 1,       /* signed byte */
    VT_U8   = 2,
    VT_I16  = 3,
    VT_U16  = 4,
    VT_I32  = 5,
    VT_U32  = 6,
    VT_F32  = 0x10,
    VT_F64  = 0x20
};

/**
 * Represents a value that is accessible by an instruction. The value may be 
 * stored in a register, in a memory location, or as an immediate.
 */
typedef struct asm_value_t
{
    enum asm_value_type type;
    union 
    {
        int8_t   i8;   /* signed byte */
        uint8_t  u8;   /* unsigned byte */
        int16_t  i16;  /* signed word */
        uint16_t u16;  /* unsigned word */
        int32_t  i32;  /* signed dword */
        uint32_t u32;  /* unsigned dword */
        float    f32;  /* single-precision */
        double   f64;  /* double-precision */
    } v;
} asm_value_t;

struct x86_operand_t
{
    enum x86_operand_type type; /* reg/imm/mem */
    asm_value_t val;

} x86_operand_t;
#endif

#if 0
#define X86_MODE_16BIT OPR_16BIT
#define X86_MODE_32BIT OPR_32BIT
#define X86_MODE_64BIT OPR_64BIT
#endif

/**
 * This file defines logical identifiers for x86 registers addressible in
 * an instruction. For performance consideration, the values of these 
 * identifiers are chosen to be consistent with the encoded values where 
 * possible; however, they are not always the same as the encoded values.
 * In particular, AH-DH need special treatment.
 *
 * A register identifier is a 16-bit value consisting of four parts:
 *
 *   --------------------------------------------------
 *   Bit     | 15 .. 12 | 11 ..  8 |  7 .. 4  |  3 .. 0 
 *   Meaning |  offset  |   size   |   type   |  number
 *   --------------------------------------------------
 *
 * Fields 'type' and 'number' defines the physical register in the CPU, e.g.
 * RAX. Fields 'size' and 'offset' defines the sub-register that is referenced
 * in the instruction, e.g. AX. All sub-registers that share a same physical
 * register have the same 'type' and 'number'. 'offset' is typically 0, which
 * indicates the lowerest bits of the register. The exceptions are AH-DH, 
 * whose offsets are 1 to indicate that they refer to the high byte.
 */

/* Enumerated values of register size. */
enum x86_reg_size
{
    R_SIZE_8BIT     = OPR_8BIT,
    R_SIZE_16BIT    = OPR_16BIT,
    R_SIZE_32BIT    = OPR_32BIT,
    R_SIZE_64BIT    = OPR_64BIT,
    R_SIZE_128BIT   = OPR_128BIT,
    R_SIZE_256BIT   = OPR_256BIT,
    R_SIZE_80BIT    = OPR_80BIT
};

/* Enumerated values of register type. */
enum x86_register_type
{
    R_TYPE_SPECIAL  = 0,
    R_TYPE_GENERAL  = 1,
    R_TYPE_SEGMENT  = 2,
    R_TYPE_CONTROL  = 3,
    R_TYPE_DEBUG    = 4,
    R_TYPE_MMX      = 5,
    R_TYPE_XMM      = 6,
    R_TYPE_YMM      = 7
};

/* Enumerated values of register offset. */
enum x86_register_offset
{
    R_OFFSET_NONE   = 0,
    R_OFFSET_HIBYTE = 1
};

/* Enumerated values of register number. */
enum x86_register_number
{
    /* ordinal numbers */
    R_NUMBER_0      = 0,
    R_NUMBER_1      = 1,
    R_NUMBER_2      = 2,
    R_NUMBER_3      = 3,
    R_NUMBER_4      = 4,
    R_NUMBER_5      = 5,
    R_NUMBER_6      = 6,
    R_NUMBER_7      = 7,
    R_NUMBER_8      = 8,
    R_NUMBER_9      = 9,
    R_NUMBER_10     = 10,
    R_NUMBER_11     = 11,
    R_NUMBER_12     = 12,
    R_NUMBER_13     = 13,
    R_NUMBER_14     = 14,
    R_NUMBER_15     = 15,

    /* special numbers for special registers */
    R_NUMBER_NONE   = 0,
    R_NUMBER_IP     = 1,
    R_NUMBER_FLAGS  = 2,
    R_NUMBER_MXCSR  = 3
};

/* Build a register identifier from its type, number, size, and offset. */
#define REG_MAKE(type, number, size, offset) \
    (((type) << 4) | (number) | ((size) << 8) | (offset) << 12)

/* Build a register identifier statically using all 4 arguments. */
#define REG_MAKE_4(type, number, bits, offset) \
    REG_MAKE(R_TYPE_##type, R_NUMBER_##number, R_SIZE_##bits##BIT, R_OFFSET_##offset)

/* Build a register identifier statically, assuming 0 offset. */
#define REG_MAKE_3(type, number, bits) REG_MAKE_4(type, number, bits, NONE)

/* Build a byte/word/dword/qword/dqword register statically. */
#define REG_MAKE_B(type, number) REG_MAKE_3(type, number, 8)
#define REG_MAKE_W(type, number) REG_MAKE_3(type, number, 16)
#define REG_MAKE_D(type, number) REG_MAKE_3(type, number, 32)
#define REG_MAKE_Q(type, number) REG_MAKE_3(type, number, 64)
#define REG_MAKE_DQ(type, number) REG_MAKE_3(type, number, 128)

/* Gets the type of a register (as enum x86_reg_type). */
#define REG_TYPE(reg)   (((reg) >> 4) & 0xf)

/* Gets the size of a register (as enum x86_reg_size). */
#define REG_SIZE(reg)   (((reg) >> 8) & 0xf)

/* Gets the offset of a register (as enum x86_register_offset). */
#define REG_OFFSET(reg) (((reg) >> 12) & 0xf)

/* Gets the number of a register (as enum x86_register_number). */
#define REG_NUMBER(reg) ((reg) & 0xf)

/** Enumerated values of x86 register identifiers. */
enum x86_register
{
    R_NONE  = 0,

    /* General purpose registers. */
    /* See Table B-2 to B-5 in Intel Reference, Volume 2, Appendix B. */

    /* ad-hoc registers */
    R_AH    = REG_MAKE_4(GENERAL, 0, 8, HIBYTE),
    R_CH    = REG_MAKE_4(GENERAL, 1, 8, HIBYTE),
    R_DH    = REG_MAKE_4(GENERAL, 2, 8, HIBYTE),
    R_BH    = REG_MAKE_4(GENERAL, 3, 8, HIBYTE),

    /* byte registers */
    R_AL    = REG_MAKE_B(GENERAL, 0),
    R_CL    = REG_MAKE_B(GENERAL, 1),
    R_DL    = REG_MAKE_B(GENERAL, 2),
    R_BL    = REG_MAKE_B(GENERAL, 3),
    R_SPL   = REG_MAKE_B(GENERAL, 4),
    R_BPL   = REG_MAKE_B(GENERAL, 5),
    R_SIL   = REG_MAKE_B(GENERAL, 6),
    R_DIL   = REG_MAKE_B(GENERAL, 7),
    R_R8L   = REG_MAKE_B(GENERAL, 8),
    R_R9L   = REG_MAKE_B(GENERAL, 9),
    R_R10L  = REG_MAKE_B(GENERAL, 10),
    R_R11L  = REG_MAKE_B(GENERAL, 11),
    R_R12L  = REG_MAKE_B(GENERAL, 12),
    R_R13L  = REG_MAKE_B(GENERAL, 13),
    R_R14L  = REG_MAKE_B(GENERAL, 14),
    R_R15L  = REG_MAKE_B(GENERAL, 15),

    /* word registers */
    R_AX    = REG_MAKE_W(GENERAL, 0),
    R_CX    = REG_MAKE_W(GENERAL, 1),
    R_DX    = REG_MAKE_W(GENERAL, 2),
    R_BX    = REG_MAKE_W(GENERAL, 3),
    R_SP    = REG_MAKE_W(GENERAL, 4),
    R_BP    = REG_MAKE_W(GENERAL, 5),
    R_SI    = REG_MAKE_W(GENERAL, 6),
    R_DI    = REG_MAKE_W(GENERAL, 7),
    R_R8W   = REG_MAKE_W(GENERAL, 8),
    R_R9W   = REG_MAKE_W(GENERAL, 9),
    R_R10W  = REG_MAKE_W(GENERAL, 10),
    R_R11W  = REG_MAKE_W(GENERAL, 11),
    R_R12W  = REG_MAKE_W(GENERAL, 12),
    R_R13W  = REG_MAKE_W(GENERAL, 13),
    R_R14W  = REG_MAKE_W(GENERAL, 14),
    R_R15W  = REG_MAKE_W(GENERAL, 15),
    
    /* dword registers */
    R_EAX   = REG_MAKE_D(GENERAL, 0),
    R_ECX   = REG_MAKE_D(GENERAL, 1),
    R_EDX   = REG_MAKE_D(GENERAL, 2),
    R_EBX   = REG_MAKE_D(GENERAL, 3),
    R_ESP   = REG_MAKE_D(GENERAL, 4),
    R_EBP   = REG_MAKE_D(GENERAL, 5),
    R_ESI   = REG_MAKE_D(GENERAL, 6),
    R_EDI   = REG_MAKE_D(GENERAL, 7),
    R_R8D   = REG_MAKE_D(GENERAL, 8),
    R_R9D   = REG_MAKE_D(GENERAL, 9),
    R_R10D  = REG_MAKE_D(GENERAL, 10),
    R_R11D  = REG_MAKE_D(GENERAL, 11),
    R_R12D  = REG_MAKE_D(GENERAL, 12),
    R_R13D  = REG_MAKE_D(GENERAL, 13),
    R_R14D  = REG_MAKE_D(GENERAL, 14),
    R_R15D  = REG_MAKE_D(GENERAL, 15),

    /* qword registers */
    R_RAX   = REG_MAKE_Q(GENERAL, 0),
    R_RCX   = REG_MAKE_Q(GENERAL, 1),
    R_RDX   = REG_MAKE_Q(GENERAL, 2),
    R_RBX   = REG_MAKE_Q(GENERAL, 3),
    R_RSP   = REG_MAKE_Q(GENERAL, 4),
    R_RBP   = REG_MAKE_Q(GENERAL, 5),
    R_RSI   = REG_MAKE_Q(GENERAL, 6),
    R_RDI   = REG_MAKE_Q(GENERAL, 7),
    R_R8    = REG_MAKE_Q(GENERAL, 8),
    R_R9    = REG_MAKE_Q(GENERAL, 9),
    R_R10   = REG_MAKE_Q(GENERAL, 10),
    R_R11   = REG_MAKE_Q(GENERAL, 11),
    R_R12   = REG_MAKE_Q(GENERAL, 12),
    R_R13   = REG_MAKE_Q(GENERAL, 13),
    R_R14   = REG_MAKE_Q(GENERAL, 14),
    R_R15   = REG_MAKE_Q(GENERAL, 15),

    /* Segment registers. See Volume 2, Appendix B, Table B-8. */
    R_ES    = REG_MAKE_W(SEGMENT, 0),
    R_CS    = REG_MAKE_W(SEGMENT, 1),
    R_SS    = REG_MAKE_W(SEGMENT, 2),
    R_DS    = REG_MAKE_W(SEGMENT, 3),
    R_FS    = REG_MAKE_W(SEGMENT, 4),
    R_GS    = REG_MAKE_W(SEGMENT, 5),
 
    /* Control registers (eee). See Volume 2, Appendix B, Table B-9. */
    R_CR0   = REG_MAKE_W(CONTROL, 0),
    R_CR2   = REG_MAKE_W(CONTROL, 2),
    R_CR3   = REG_MAKE_W(CONTROL, 3),
    R_CR4   = REG_MAKE_W(CONTROL, 4),

    /* Debug registers (eee). See Volume 2, Appendix B, Table B-9. */
    R_DR0   = REG_MAKE_W(DEBUG, 0),
    R_DR1   = REG_MAKE_W(DEBUG, 1),
    R_DR2   = REG_MAKE_W(DEBUG, 2),
    R_DR3   = REG_MAKE_W(DEBUG, 3),
    R_DR6   = REG_MAKE_W(DEBUG, 6),
    R_DR7   = REG_MAKE_W(DEBUG, 7),

    /* MMX registers. */
    R_MM0   = REG_MAKE_Q(MMX, 0),
    R_MM1   = REG_MAKE_Q(MMX, 1),
    R_MM2   = REG_MAKE_Q(MMX, 2),
    R_MM3   = REG_MAKE_Q(MMX, 3),
    R_MM4   = REG_MAKE_Q(MMX, 4),
    R_MM5   = REG_MAKE_Q(MMX, 5),
    R_MM6   = REG_MAKE_Q(MMX, 6),
    R_MM7   = REG_MAKE_Q(MMX, 7),

    /* XMM registers. */
    R_XMM0  = REG_MAKE_DQ(XMM, 0),
    R_XMM1  = REG_MAKE_DQ(XMM, 1),
    R_XMM2  = REG_MAKE_DQ(XMM, 2),
    R_XMM3  = REG_MAKE_DQ(XMM, 3),
    R_XMM4  = REG_MAKE_DQ(XMM, 4),
    R_XMM5  = REG_MAKE_DQ(XMM, 5),
    R_XMM6  = REG_MAKE_DQ(XMM, 6),
    R_XMM7  = REG_MAKE_DQ(XMM, 7),
    R_XMM8  = REG_MAKE_DQ(XMM, 8),
    R_XMM9  = REG_MAKE_DQ(XMM, 9),
    R_XMM10 = REG_MAKE_DQ(XMM, 10),
    R_XMM11 = REG_MAKE_DQ(XMM, 11),
    R_XMM12 = REG_MAKE_DQ(XMM, 12),
    R_XMM13 = REG_MAKE_DQ(XMM, 13),
    R_XMM14 = REG_MAKE_DQ(XMM, 14),
    R_XMM15 = REG_MAKE_DQ(XMM, 15),

    /* Special registers. */
    R_IP    = REG_MAKE_W(SPECIAL, IP),
    R_FLAGS = REG_MAKE_W(SPECIAL, FLAGS),
    R_EIP   = REG_MAKE_D(SPECIAL, IP),
    R_EFLAGS= REG_MAKE_D(SPECIAL, FLAGS),
    R_MXCSR = REG_MAKE_D(SPECIAL, MXCSR)
};

typedef struct x86_options_t
{
    int mode;           /* 16, 32 or 64 bit */
} x86_options_t;

/* Gets the size of the decoding mode (as enum x86_opr_size). */
#define CPU_SIZE(opt) ((opt)->mode)

/**
 * Enumerated values of x86 jump conditions (tttn).
 * See Intel Reference, Volume 2, Appendix B, Table B-10.
 */
enum x86_condition
{
    C_O   = 0,
    C_NO  = 1,
    C_B   = 2,  C_NAE = C_B,
    C_NB  = 3,  C_AE  = C_NB,
    C_E   = 4,  C_Z   = C_E,
    C_NE  = 5,  C_NZ  = C_NE,
    C_BE  = 6,  C_NA  = C_BE,
    C_NBE = 7,  C_A   = C_NBE,
    C_S   = 8,
    C_NS  = 9,
    C_P   = 10, C_PE  = C_P,
    C_NP  = 11, C_PO  = C_NP,
    C_L   = 12, C_NGE = C_L,
    C_NL  = 13, C_GE  = C_NL,
    C_LE  = 14, C_NG  = C_LE,
    C_NLE = 15, C_G   = C_NLE
};

/**
 * Enumerated values of instruction prefixes. Zero, one, or more than one
 * prefixes may be specified for an instruction. A prefix, if present, 
 * modifies the meaning of the instruction. There are four groups of prefixes.
 * Only one prefix from each group may be present in an instruction.
 */
#if 0
enum x86_insn_prefix
{
    PFX_NONE  = 0,

    /* Group 1: lock and repeat prefixes */
    PFX_LOCK  = 1, /* F0 */
    PFX_REPNZ = 2, /* F2 */
    PFX_REPNE = PFX_REPNZ,
    PFX_REP   = 3, /* F3 */
    PFX_REPZ  = PFX_REP,
    PFX_REPE  = PFX_REPZ,

    /* Group 2: segment override or branch hints */
    PFX_ES      = 0x10, /* 26 */
    PFX_CS      = 0x20, /* 2E */
    PFX_SS      = 0x30, /* 36 */
    PFX_DS      = 0x40, /* 3E */
    PFX_FS      = 0x50, /* 64 */
    PFX_GS      = 0x60, /* 65 */
    PFX_BRANCH_TAKEN        = 0x20, /* 2E */
    PFX_BRANCH_NOT_TAKEN    = 0x40, /* 3E */

    /* Group 3: operand-size override */
    PFX_OPERAND_SIZE = 0x100, /* 66 */
    
    /* Group 4: address-size override */
    PFX_ADDRESS_SIZE = 0x1000 /* 67 */
};

#define PFX_GROUP(pfx, grp) ((pfx) & (0xf << (((grp)-1)*4)))
#else
enum x86_insn_prefix
{
    /* Group 1: lock and repeat prefixes */
    PFX_LOCK  = 0xF0,
    PFX_REPNZ = 0xF2,
    PFX_REPNE = PFX_REPNZ,
    PFX_REP   = 0xF3,
    PFX_REPZ  = PFX_REP,
    PFX_REPE  = PFX_REP,

    /* Group 2: segment override or branch hints */
    PFX_ES      = 0x26,
    PFX_CS      = 0x2E,
    PFX_SS      = 0x36,
    PFX_DS      = 0x3E,
    PFX_FS      = 0x64,
    PFX_GS      = 0x65,
    PFX_BRANCH_TAKEN     = 0x2E,
    PFX_BRANCH_NOT_TAKEN = 0x3E,

    /* Group 3: operand-size override */
    PFX_OPERAND_SIZE = 0x66,
    
    /* Group 4: address-size override */
    PFX_ADDRESS_SIZE = 0x67
};
#endif

/**
 * Mnemonics for x86 instructions. This provides a direct translation between
 * a machine instruction and an assembly mnemonic. For binary compatibility, 
 * the value of the enum members must not change; new members must be appended
 * to the end of the enum list.
 */
enum x86_insn_mnemonic
{
    I_NONE = 0,

#define I(insn) I_##insn,
#include "x86_mnemonic.inc"
#undef I

    I_XXXX
};

/** Maximum number of operands in a single instruction. */
#define MAX_OPERANDS 4

/**
 * Represents a decoded x86 instruction.
 */
typedef struct x86_insn_t
{
    unsigned char prefix[5]; /* instruction prefix from each group */
    /* enum x86_insn_prefix   prefix;  /* instruction prefix */
    enum x86_insn_mnemonic op;      /* instruction mnemonic */
    x86_opr_t oprs[MAX_OPERANDS]; /* at most 4 operands */
} x86_insn_t;

/* Decodes an instruction. Returns the number of bytes consumed. */
int x86_decode(
    const unsigned char *code_begin,
    const unsigned char *code_end,
    x86_insn_t *insn, 
    const x86_options_t *opt);

#define X86_FMT_SYNTAX(f) ((f) & 1)
#define X86_FMT_INTEL   0
#define X86_FMT_ATT     1

#define X86_FMT_CASE(f) ((f) & 2)
#define X86_FMT_LOWER   0
#define X86_FMT_UPPER   2

typedef unsigned int x86_fmt_t;

/* Formats an instruction as a string. */
void x86_format(
    const x86_insn_t *insn,
    char buffer[256],
    x86_fmt_t fmt);

#ifdef __cplusplus
}
#endif

#endif /* X86_CODEC_H */
