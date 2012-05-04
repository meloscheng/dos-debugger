/*
 * x86_codec.h - routines for encoding/decoding x86 instructions.
 */

#ifndef X86_CODEC_H
#define X86_CODEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Enumerated values for the type of an operand. */
enum asm_operand_type
{
	OT_NONE = 0,   /* the operand is not used */
	OT_REG = 1,    /* the operand is a register */
	OT_MEM = 2,    /* the operand is a memory location */
	OT_IMM = 3     /* the operand is an immediate */
};

/**
 * Enumerated values for the type of a value accessible by an instruction.
 * The value may be stored in a register, in a memory location, or as an
 * immediate.
 */
typedef enum asm_value_type
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
} asm_value_type;

/**
 * Represents a value that is accessible by an instruction. The value may be 
 * stored in a register, in a memory location, or as an immediate.
 */
typedef struct asm_value_t
{
	asm_value_type type;
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

typedef struct asm_reg_t
{
    char t;
};


typedef struct asm_operand_t
{
	asm_operand_type type; /* type of operand */

} asm_operand_t;

typedef struct asm_insn_t
{
	int optype;                    /* operation type; should be one of the
								    * asm_insn_type values.
									*/
	asm_operand_t operands[3];     /* at most 3 operands */
} asm_insn_t;

/**
 * Instruction prefixes, which modifies the meaning of the instruction.
 */
enum asm_insn_prefix
{
    P_NONE  = 0,
    P_LOCK  = 1,
    P_REP   = 2,
    P_REPZ  = 3, P_REPE  = P_REPZ,
    P_REPNZ = 4, P_REPNE = P_REPNZ
};


typedef struct x86_options_t
{
    int mode; /* ignored */
} x86_options_t;

int x86_decode(const void *code, asm_insn_t *insn, const x86_options_t *opt);

/**
 * Encoding of x86 general purpose registers. 
 * See Table B-2 to B-5 in Intel Reference, Volume 2, Appendix B.
 */
enum x86_general_register
{
    R_AX = 0,  /* AL, AX, EAX, RAX */
    R_CX = 1,  /* CL, CX, ECX, RCX */
    R_DX = 2,  /* DL, DX, EDX, RDX */
    R_BX = 3,  /* BL, BX, EBX, RBX */
    R_SP = 4,  /* AH, SP, ESP, RSP */
    R_BP = 5,  /* CH, BP, EBP, RBP */
    R_SI = 6,  /* DH, SI, ESI, RSI */
    R_DI = 7   /* BH, DI, EDI, RDI */
};

/**
 * Encoding of x86 segment registers (sreg).
 * See Table B-8 in Intel Reference, Volume 2, Appendix B.
 */
enum x86_segment_register
{
    R_ES = 0,
    R_CS = 1,
    R_SS = 2,
    R_DS = 3,
    R_FS = 4,
    R_GS = 5
};

/**
 * Encoding of x86 control registers (eee).
 * See Table B-9 in Intel Reference, Volume 2, Appendix B.
 */
enum x86_control_register
{
    R_CR0 = 0,
    R_CR2 = 2,
    R_CR3 = 3,
    R_CR4 = 4
};

/**
 * Encoding of x86 debug registers (eee).
 * See Table B-9 in Intel Reference, Volume 2, Appendix B.
 */
enum x86_debug_register
{
    R_DR0 = 0,
    R_DR1 = 1,
    R_DR2 = 2,
    R_DR3 = 3,
    R_DR6 = 6,
    R_DR7 = 7
};

/**
 * Encoding of x86 jump conditions (tttn).
 * See Table B-10 in Intel Reference, Volume 2, Appendix B.
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

#ifdef __cplusplus
}
#endif

#endif /* X86_CODEC_H */
