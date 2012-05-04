/*
 * decode.c - routines to decode x86 instructions.
 */

#include "x86_codec.h"

typedef struct x86_opcode_entry
{
    int insn;           /* type of instruction */
    int operands[4];    /* definition of operands */
} x86_opcode_entry;

/*
 * An operand is denoted in the form "Zz", with a few additional special 
 * values for specific cases. The first letter specifies the addressing 
 * method, and the rest letters specify the operand type.
 * See Appendix A.2 in Intel Reference, Volume 2.
 */
enum x86_operand_notation
{
    O_NONE = 0,

    /* Addressing methods */
    AM_A = 0x0100,  /* address encoded in immediate */
    AM_C = 0x0300,  /* REG(modrm) specifies control register */
    AM_E = 0x0500,  /* modrm specifies register or memory */
    AM_F = 0x0600,  /* EFLAGS or RFLAGS */
    AM_G = 0x0700,  /* REG(modrm) specifies general register */
    AM_I = 0x0900,  /* value encoded in immediate */
    AM_J = 0x0a00,  /* immediate specifies relative offset */
    AM_M = 0x0d00,  /* modrm specifies memory */
    AM_O = 0x0f00,  /* ?? */
    AM_R = 0x1200,  /* RM(modrm) specifies general register */
    AM_S = 0x1300,  /* REG(modrm) specifies segment register */
    AM_X = 0x1800,  /* DS:rSI */
    AM_Y = 0x1900,  /* ES:rDI */

    /* Operand type */
    OT_b = 0x02,    /* byte */
    OT_v = 0x16,    /* word (16-bit), dword (32-bit), or qword (64-bit) */
    OT_w = 0x17,    /* word */
    OT_z = 0x1a,    /* word (16-bit) or dword (32- and 64-bit) */

    /* Combination of addressing method and operand type */
#define COMBINE(Z,z) O_##Z##z = AM_##Z | OT_##z
    COMBINE(E,b),
    COMBINE(E,v),
    COMBINE(E,w),
    COMBINE(G,b),
    COMBINE(G,v),
    COMBINE(G,w),
    COMBINE(I,b),
    COMBINE(I,z),
    COMBINE(M,a),
    COMBINE(X,b),
    COMBINE(X,z),
    COMBINE(Y,b),
    COMBINE(Y,z),    
#undef COMBINE

    /* Specific registers */
    O_ES = 0x10000,
    O_CS = 0x10001,
    O_SS = 0x10002,
    O_DS = 0x10003,

    O_AL = 0x20000,
    O_CL = 0x20001,
    O_DL = 0x20002,
    O_BL = 0x20003,

    O_rAX = 0x30000, /* AX, EAX, or RAX */
    O_rCX = 0x30001,
    O_rDX = 0x30002,
    O_rBX = 0x30003,
    O_rSP = 0x30004,
    O_rBP = 0x30005,
    O_rSI = 0x30006,
    O_rDI = 0x30007,

    O_eAX = 0x40000, /* AX or EAX */
    O_eCX = 0x40001,
    O_eDX = 0x40002,
    O_eBX = 0x40003,
    O_eSP = 0x40004,
    O_eBP = 0x40005,
    O_eSI = 0x40006,
    O_eDI = 0x40007,

    O_AX = 0x50000, /* AX */
    O_CX = 0x50001,
    O_DX = 0x50002,
    O_BX = 0x50003,
    O_SP = 0x50004,
    O_BP = 0x50005,
    O_SI = 0x50006,
    O_DI = 0x50007,

    O_XXXX
};

#define OP0(insn) { I_##insn, { 0 } }
#define OP1(insn, oper1) { I_##insn, { O_##oper1 } }
#define OP2(insn, oper1, oper2) { I_##insn, { O_##oper1, O_##oper2 } }
#define OP3(insn, oper1, oper2, oper3) { I_##insn, { O_##oper1, O_##oper2, O_##oper3 } }
#define OP_EMPTY { 0 }
#define OP_EMPTY_4 OP_EMPTY, OP_EMPTY, OP_EMPTY, OP_EMPTY
#define OP_EMPTY_8 OP_EMPTY_4, OP_EMPTY_4

/*
 * Table for one-byte opcodes. 
 * See Table A-2 in Intel Reference, Volume 2, Appendix A.
 */
static x86_opcode_entry x86_opcode_map_1byte[256] = 
{
    /* 00 */ OP2(ADD, Eb, Gb),
    /* 01 */ OP2(ADD, Ev, Gv),
    /* 02 */ OP2(ADD, Gb, Eb),
    /* 03 */ OP2(ADD, Gv, Ev),
    /* 04 */ OP2(ADD, AL, Ib),
    /* 05 */ OP2(ADD, rAX, Iz),
    /* 06 */ OP1(PUSH, ES), /* i64 */
    /* 07 */ OP1(POP, ES),  /* i64 */
    /* 08 */ OP2(OR, Eb, Gb),
    /* 09 */ OP2(OR, Ev, Gv),
    /* 0A */ OP2(OR, Gb, Eb),
    /* 0B */ OP2(OR, Gv, Ev),
    /* 0C */ OP2(OR, AL, Ib),
    /* 0D */ OP2(OR, rAX, Iz),
    /* 0E */ OP1(PUSH, CS), /* i64 */
    /* 0F */ OP_EMPTY,      /* 2-byte escape */

    /* 10 */ OP2(ADC, Eb, Gb),
    /* 11 */ OP2(ADC, Ev, Gv),
    /* 12 */ OP2(ADC, Gb, Eb),
    /* 13 */ OP2(ADC, Gv, Ev),
    /* 14 */ OP2(ADC, AL, Ib),
    /* 15 */ OP2(ADC, rAX, Iz),
    /* 16 */ OP1(PUSH, SS), /* i64 */
    /* 17 */ OP1(POP, SS), /* i64 */
    /* 18 */ OP2(SBB, Eb, Gb),
    /* 19 */ OP2(SBB, Ev, Gv),
    /* 1A */ OP2(SBB, Gb, Eb),
    /* 1B */ OP2(SBB, Gv, Ev),
    /* 1C */ OP2(SBB, AL, Ib),
    /* 1D */ OP2(SBB, rAX, Iz),
    /* 1E */ OP1(PUSH, DS), /* i64 */
    /* 1F */ OP1(POP, DS), /* i64 */

    /* 20 */ OP2(AND, Eb, Gb),
    /* 21 */ OP2(AND, Ev, Gv),
    /* 22 */ OP2(AND, Gb, Eb),
    /* 23 */ OP2(AND, Gv, Ev),
    /* 24 */ OP2(AND, AL, Ib),
    /* 25 */ OP2(AND, rAX, Iz),
    /* 26 */ OP_EMPTY, /* SEG=ES (prefix) */
    /* 27 */ OP0(DAA), /* i64 */
    /* 28 */ OP2(SUB, Eb, Gb),
    /* 29 */ OP2(SUB, Ev, Gv),
    /* 2A */ OP2(SUB, Gb, Eb),
    /* 2B */ OP2(SUB, Gv, Ev),
    /* 2C */ OP2(SUB, AL, Ib),
    /* 2D */ OP2(SUB, rAX, Iz),
    /* 2E */ OP_EMPTY, /* SEG=CS (prefix) */
    /* 2F */ OP0(DAS), /* i64 */

    /* 30 */ OP2(XOR, Eb, Gb),
    /* 31 */ OP2(XOR, Ev, Gv),
    /* 32 */ OP2(XOR, Gb, Eb),
    /* 33 */ OP2(XOR, Gv, Ev),
    /* 34 */ OP2(XOR, AL, Ib),
    /* 35 */ OP2(XOR, rAX, Iz),
    /* 36 */ OP_EMPTY, /* SEG=SS (prefix) */
    /* 37 */ OP0(AAA), /* i64 */
    /* 38 */ OP2(CMP, Eb, Gb),
    /* 39 */ OP2(CMP, Ev, Gv),
    /* 3A */ OP2(CMP, Gb, Eb),
    /* 3B */ OP2(CMP, Gv, Ev),
    /* 3C */ OP2(CMP, AL, Ib),
    /* 3D */ OP2(CMP, rAX, Iz),
    /* 3E */ OP_EMPTY, /* SEG=DS (prefix) */
    /* 3F */ OP0(AAS), /* i64 */

    /* 40 */ OP1(INC, eAX), /* i64, REX */
    /* 41 */ OP1(INC, eCX), /* i64, REX.B */
    /* 42 */ OP1(INC, eDX), /* i64, REX.X */
    /* 43 */ OP1(INC, eBX), /* i64, REX.XB */
    /* 44 */ OP1(INC, eSP), /* i64, REX.R */
    /* 45 */ OP1(INC, eBP), /* i64, REX.RB */
    /* 46 */ OP1(INC, eSI), /* i64, REX.RX */
    /* 47 */ OP1(INC, eDI), /* i64, REX.RXB */
    /* 48 */ OP1(DEC, eAX), /* i64, REX.W */
    /* 49 */ OP1(DEC, eCX), /* i64, REX.WB */
    /* 4A */ OP1(DEC, eDX), /* i64, REX.WX */
    /* 4B */ OP1(DEC, eBX), /* i64, REX.WXB */
    /* 4C */ OP1(DEC, eSP), /* i64, REX.WR */
    /* 4D */ OP1(DEC, eBP), /* i64, REX.WRB */
    /* 4E */ OP1(DEC, eSI), /* i64, REX.WRX */
    /* 4F */ OP1(DEC, eDI), /* i64, REX.WRXB */

    /* 50 */ OP1(PUSH, rAX), /* d64 */
    /* 51 */ OP1(PUSH, rCX), /* d64 */
    /* 52 */ OP1(PUSH, rDX), /* d64 */
    /* 53 */ OP1(PUSH, rBX), /* d64 */
    /* 54 */ OP1(PUSH, rSP), /* d64 */
    /* 55 */ OP1(PUSH, rBP), /* d64 */
    /* 56 */ OP1(PUSH, rSI), /* d64 */
    /* 57 */ OP1(PUSH, rDI), /* d64 */
    /* 58 */ OP1(POP, rAX), /* d64 */
    /* 59 */ OP1(POP, rCX), /* d64 */
    /* 5A */ OP1(POP, rDX), /* d64 */
    /* 5B */ OP1(POP, rBX), /* d64 */
    /* 5C */ OP1(POP, rSP), /* d64 */
    /* 5D */ OP1(POP, rBP), /* d64 */
    /* 5E */ OP1(POP, rSI), /* d64 */
    /* 5F */ OP1(POP, rDI), /* d64 */

    /* 60 */ OP0(PUSHA), /* i64 */
    /* 61 */ OP0(POPA), /* i64 */
    /* 62 */ OP2(BOUND, Gv, Ma), /* i64 */
    /* 63 */ OP2(ARPL, Ew, Gw), /* i64, MOVSXD (o64) */
    /* 64 */ OP_EMPTY, /* SEG=FS (prefix) */
    /* 65 */ OP_EMPTY, /* SEG=GS (prefix) */
    /* 66 */ OP_EMPTY, /* operand size (prefix) */
    /* 67 */ OP_EMPTY, /* address size (prefix) */
    /* 68 */ OP1(PUSH, Iz), /* d64 */
    /* 69 */ OP3(IMUL, Gv, Ev, Iz),
    /* 6A */ OP1(PUSH, Ib), /* d64 */
    /* 6B */ OP3(IMUL, Gv, Ev, Ib),
    /* 6C */ OP2(INS, Yb, DX),
    /* 6D */ OP2(INS, Yz, DX),
    /* 6E */ OP2(OUTS, DX, Xb),
    /* 6F */ OP2(OUTS, DX, Xz),

    /* f64 - The operand size is forced to a 64-bit operand size
     * when in 64-bit mode, regardless of size prefix. 
     */
    /* 70 */ OP0(JO),
    /* 71 */ OP0(JNO),
    /* 72 */ OP0(JB),
    /* 73 */ OP0(JNB),
    /* 74 */ OP0(JE),
    /* 75 */ OP0(JNE),
    /* 76 */ OP0(JBE),
    /* 77 */ OP0(JNBE),
    /* 78 */ OP0(JS),
    /* 79 */ OP0(JNS),
    /* 7A */ OP0(JP),
    /* 7B */ OP0(JNP),
    /* 7C */ OP0(JL),
    /* 7D */ OP0(JNL),
    /* 7E */ OP0(JLE),
    /* 7F */ OP0(JNLE),


};

int x86_decode(const void *code, asm_insn_t *insn, const x86_options_t *opt)
{
	return -1;
}
