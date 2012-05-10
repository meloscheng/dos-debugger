/*
 * decode.c - routines to decode x86 instructions.
 */

#include "x86_codec.h"
#include <memory.h>

/* Specialized instruction reader. */
typedef struct x86_insn_reader_t
{
    unsigned char buffer[20];       /* buffer used when few bytes left */
    const unsigned char *prefix;    /* pointer to beginning of instruction */
    const unsigned char *opcode;    /* pointer to opcode */
    const unsigned char *modrm;     /* pointer to modrm byte */
    const unsigned char *end;       /* pointer to end of insn + 1 */
} x86_insn_reader_t;

/* Initializes a bytecode reader to read code from a given part of memory. */
static void 
init_reader(x86_insn_reader_t *rd, const unsigned char *begin, const unsigned char *end)
{
    if (end - begin < sizeof(rd->buffer))
    {
        memset(rd->buffer, 0xcc, sizeof(rd->buffer)); /* debug token */
        memcpy(rd->buffer, begin, end - begin);
        rd->prefix = rd->buffer;
    }
    else
    {
        rd->prefix = begin;
    }
    rd->opcode = rd->modrm = rd->end = rd->prefix;
}

static uint8_t read_byte(x86_insn_reader_t *rd)
{
    const unsigned char *p = rd->end;
    rd->end++;
    return *p;
}

static uint16_t read_word(x86_insn_reader_t *rd)
{
    const unsigned char *p = rd->end;
    rd->end += 2;
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t read_dword(x86_insn_reader_t *rd)
{
    const unsigned char *p = rd->end;
    rd->end += 4;
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) 
        | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint32_t read_imm(x86_insn_reader_t *rd, int size)
{
    return (size == OPR_8BIT)? read_byte(rd) :
        (size == OPR_16BIT)? read_word(rd) :
        (size == OPR_32BIT)? read_dword(rd) : 0;
}

static unsigned char read_modrm(x86_insn_reader_t *rd)
{
    if (rd->end == rd->modrm)
        rd->end++;
    return *rd->modrm;
}

/* Marks the next byte as ModR/M. */
static void mark_modrm(x86_insn_reader_t *rd)
{
    rd->modrm = rd->end;
}

/* Returns the MOD part of a ModR/M byte (0-3). */
#define MOD(b) (((b) >> 6) & 0x3)

/* Returns the REG part of a ModR/M byte (0-7). */
#define REG(b) (((b) >> 3) & 0x7)

/* Returns the RM part of a ModR/M byte (0-7). */
#define RM(b)  ((b) & 0x7)

/*
 * Represents the encoding specification for an instruction. For performance
 * reason, the spec is stored in a 64-bit integer, as follows:
 *
 * Byte 0-1: instruction mnemonic, interpreted as a signed 16-bit integer.
 *         - If this value is positive, it should be one of the values defined
 *           in enum x86_insn_mnemonic.
 *         - If this value is zero, it designates an invalid instruction.
 *         - If this value is negative, it represents an opcode extension.
 * Byte 2: operand spec 1.
 * Byte 3: operand spec 2.
 * Byte 4: operand spec 3.
 * Byte 5: operand spec 4.
 * Byte 6: reserved; must be zero.
 * Byte 7: reserved; must be zero.
 *
 * If any of the operands are not used, the spec byte should be set to 0.
 */
typedef uint64_t x86_insn_spec_t;

/*
 * Specifies the encoding of an operand. Most operands are encoded in the form
 * "Zz", where "Z" specifies the addressing method and "z" specifies the data
 * type. These encodings are represented by a value using 16 bits. 
 *
 * The rest operands are encoded with special values. These encodings are
 * represented with a value above 0x10000.
 *
 * The special value 0 means the operand is not used.
 *
 * See Intel Reference, Volume 2, Appendix A.2 for an explanation of the 
 * abbreviations for addressing method and data type.
 */
enum x86_opr_spec
{
    O_NONE = 0,

    /* General operand */
    O_Ap,
    O_Eb, O_Ep, O_Ev, O_Ew,
    O_Fv,
    O_Gb, O_Gv, O_Gw, O_Gz,
    O_Ib, O_Iv, O_Iw, O_Iz,
    O_Jb, O_Jz,
    O_Ma, O_Mp, O_Mw,
    O_Ob, O_Ov,
    O_Rv,
    O_Sw,
    O_Xb, O_Xv, O_Xz,
    O_Yb, O_Yv, O_Yz,

    /* Immediate */
    O_n = 0x80,
    O_1 = O_n + 1,
    O_3 = O_n + 3,

    /* Segment registers. */
    O_XS = 0x90,
    O_ES = O_XS + 0,
    O_CS = O_XS + 1,
    O_SS = O_XS + 2,
    O_DS = O_XS + 3,

    /* Byte registers. */
    O_XL = 0xa0,
    O_AL = O_XL + 0,
    O_CL = O_XL + 1,
    O_DL = O_XL + 2,
    O_BL = O_XL + 3,

    O_XH = 0xa4,
    O_AH = O_XH + 0,
    O_CH = O_XH + 1,
    O_DH = O_XH + 2,
    O_BH = O_XH + 3,

    /* 16-bit generic registers */
    O_XX = 0xb0,
    O_AX = O_XX + 0,
    O_CX = O_XX + 1,
    O_DX = O_XX + 2,
    O_BX = O_XX + 3,
    O_SP = O_XX + 4,
    O_BP = O_XX + 5,
    O_SI = O_XX + 6,
    O_DI = O_XX + 7,

    /* XX in 16-bit mode, EXX in 32- or 64-bit mode */
    O_eXX = 0xc0,
    O_eAX = O_eXX + 0,
    O_eCX = O_eXX + 1,
    O_eDX = O_eXX + 2,
    O_eBX = O_eXX + 3,
    O_eSP = O_eXX + 4,
    O_eBP = O_eXX + 5,
    O_eSI = O_eXX + 6,
    O_eDI = O_eXX + 7,

    /* XX in 16-bit mode, EXX in 32-bit mode, RXX in 64-bit mode */
    O_rXX = 0xd0,
    O_rAX = O_rXX + 0,
    O_rCX = O_rXX + 1,
    O_rDX = O_rXX + 2,
    O_rBX = O_rXX + 3,
    O_rSP = O_rXX + 4,
    O_rBP = O_rXX + 5,
    O_rSI = O_rXX + 6,
    O_rDI = O_rXX + 7,

    O_XXXX
};

/* Build an encoding specification from scratch. */
#define SPEC_MAKE(op,opr1,opr2,opr3,opr4) \
    ( (uint64_t)(uint16_t)(int16_t)(op) | ((uint64_t)(opr1)<<16) | ((uint64_t)(opr2)<<24) \
    | ((uint64_t)(opr3)<<32) | ((uint64_t)(opr4)<<40) )

/* Get the operation in an encoding specification. */
#define SPEC_INSN(spec) ((int16_t)((spec) & 0xffff))

/* Get the given operand (zero-based) in an encoding specification. */
#define SPEC_OPERAND(spec,i) ((uint8_t)(((spec)>>(16+(i)*8))&0xff))

/* Get the operands part of an encoding specification. */
#define SPEC_OPERANDS(spec) ((spec) & 0xffffffffffff0000ULL)

/* Merges two encoding specifications. */
#define SPEC_MERGE(spec1,spec2) ((spec1)|(spec2))

#define OP4(insn, oper1, oper2, oper3, oper4) SPEC_MAKE(I_##insn, O_##oper1, O_##oper2, O_##oper3, O_##oper4)
#define OP3(insn, oper1, oper2, oper3) OP4(insn, oper1, oper2, oper3, NONE)
#define OP2(insn, oper1, oper2) OP3(insn, oper1, oper2, NONE)
#define OP1(insn, oper1) OP2(insn, oper1, NONE)
#define OP0(insn) OP1(insn, NONE)
#define OP_EMPTY  OP0(NONE)
#define OP_EMPTY_4 OP_EMPTY, OP_EMPTY, OP_EMPTY, OP_EMPTY
#define OP_EMPTY_8 OP_EMPTY_4, OP_EMPTY_4

enum _extended_opcode_pseudo_insn
{
    I__EXT1 = -1,
    I__EXT1A = -2,
    I__EXT2 = -3,
    I__EXT3 = -4,
    I__EXT4 = -5,
    I__EXT5 = -6,
    I__EXT6 = -7,
    I__EXT7 = -8,
    I__EXT8 = -9,
    I__EXT11 = -10
};

/*
 * Instruction encoding specification for one-byte opcodes. 
 * See Table A-2 in Intel Reference, Volume 2, Appendix A.
 */
static const x86_insn_spec_t x86_opcode_map_1byte[256] = 
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
    /* 70 */ OP1(JO, Jb),
    /* 71 */ OP1(JNO, Jb),
    /* 72 */ OP1(JB, Jb),
    /* 73 */ OP1(JNB, Jb),
    /* 74 */ OP1(JE, Jb),
    /* 75 */ OP1(JNE, Jb),
    /* 76 */ OP1(JBE, Jb),
    /* 77 */ OP1(JNBE, Jb),
    /* 78 */ OP1(JS, Jb),
    /* 79 */ OP1(JNS, Jb),
    /* 7A */ OP1(JP, Jb),
    /* 7B */ OP1(JNP, Jb),
    /* 7C */ OP1(JL, Jb),
    /* 7D */ OP1(JNL, Jb),
    /* 7E */ OP1(JLE, Jb),
    /* 7F */ OP1(JNLE, Jb),

    /* 80 */ OP2(_EXT1, Eb, Ib),
    /* 81 */ OP2(_EXT1, Ev, Iz),
    /* 82 */ OP2(_EXT1, Eb, Ib), /* i64 ??? TBD */
    /* 83 */ OP2(_EXT1, Ev, Ib),
    /* 84 */ OP2(TEST, Eb, Gb),
    /* 85 */ OP2(TEST, Ev, Gv),
    /* 86 */ OP2(XCHG, Eb, Gb),
    /* 87 */ OP2(XCHG, Ev, Gv),
    /* 88 */ OP2(MOV, Eb, Gb),
    /* 89 */ OP2(MOV, Ev, Gv),
    /* 8A */ OP2(MOV, Gb, Eb),
    /* 8B */ OP2(MOV, Gv, Ev),
    /* 8C */ OP2(MOV, Ev, Sw),
    /* 8D */ OP2(LEA, Gv, Mp), /* ??? missing TBD */
    /* 8E */ OP2(MOV, Sw, Ew),
    /* 8F */ OP0(_EXT1A), /* POP(d74) Ev */

    /* 90 */ OP0(NOP), /* PAUSE (F3), XCHG r8, rAX */
    /* 91 */ OP2(XCHG, rCX, rAX),
    /* 92 */ OP2(XCHG, rDX, rAX),
    /* 93 */ OP2(XCHG, rBX, rAX),
    /* 94 */ OP2(XCHG, rSP, rAX),
    /* 95 */ OP2(XCHG, rBP, rAX),
    /* 96 */ OP2(XCHG, rSI, rAX),
    /* 97 */ OP2(XCHG, rDI, rAX),
    /* 98 */ OP0(CBW), /* CWDE/CDQE */
    /* 99 */ OP0(CWD), /* CDQ/CQO */
    /* 9A */ OP1(CALLF, Ap), /* i64 */
    /* 9B */ OP0(FWAIT), /* WAIT */
    /* 9C */ OP1(PUSHF, Fv), /* PUSHF/D/Q(d64) */
    /* 9D */ OP1(POPF, Fv), /* POPF/D/Q(d64) */
    /* 9E */ OP0(SAHF),
    /* 9F */ OP0(LAHF),

    /* A0 */ OP2(MOV, AL, Ob),
    /* A1 */ OP2(MOV, rAX, Ov),
    /* A2 */ OP2(MOV, Ob, AL),
    /* A3 */ OP2(MOV, Ov, rAX),
    /* A4 */ OP2(MOVS, Yb, Xb), /* MOVS/B */
    /* A5 */ OP2(MOVS, Yv, Xv), /* MOVS/W/D/Q */
    /* A6 */ OP2(CMPS, Xb, Yb), /* CMPS/B */
    /* A7 */ OP2(CMPS, Xv, Yv), /* CMPS/W/D */
    /* A8 */ OP2(TEST, AL, Ib),
    /* A9 */ OP2(TEST, rAX, Iz),
    /* AA */ OP2(STOS, Yb, AL), /* STOS/B */
    /* AB */ OP2(STOS, Yv, rAX), /* STOS/W/D/Q */
    /* AC */ OP2(LODS, AL, Xb), /* LODS/B */
    /* AD */ OP2(LODS, rAX, Xv), /* LODS/W/D/Q */
    /* AE */ OP2(SCAS, AL, Yb), /* SCAS/B */ /* TBD */
    /* AF */ OP2(SCAS, rAX, Xv), /* SCAS/W/D/Q */ /* TBD */

    /* B0 */ OP2(MOV, AL, Ib),
    /* B1 */ OP2(MOV, CL, Ib),
    /* B2 */ OP2(MOV, DL, Ib),
    /* B3 */ OP2(MOV, BL, Ib),
    /* B4 */ OP2(MOV, AH, Ib),
    /* B5 */ OP2(MOV, CH, Ib),
    /* B6 */ OP2(MOV, DH, Ib),
    /* B7 */ OP2(MOV, BH, Ib),
    /* B8 */ OP2(MOV, rAX, Iv),
    /* B9 */ OP2(MOV, rCX, Iv),
    /* BA */ OP2(MOV, rDX, Iv),
    /* BB */ OP2(MOV, rBX, Iv),
    /* BC */ OP2(MOV, rSP, Iv),
    /* BD */ OP2(MOV, rBP, Iv),
    /* BE */ OP2(MOV, rSI, Iv),
    /* BF */ OP2(MOV, rDI, Iv),

    /* C0 */ OP2(_EXT2, Eb, Ib),
    /* C1 */ OP2(_EXT2, Ev, Ib),
    /* C2 */ OP1(RETN, Iw), /* f64 */
    /* C3 */ OP0(RETN),     /* f64 */
    /* C4 */ OP2(LES, Gz, Mp), /* i64; VEX+2byte */
    /* C5 */ OP2(LDS, Gz, Mp), /* i64; VEX+1byte */
    /* C6 */ OP2(_EXT11, Eb, Ib),
    /* C7 */ OP2(_EXT11, Ev, Iz),
    /* C8 */ OP2(ENTER, Iw, Ib),
    /* C9 */ OP0(LEAVE), /* d64 */
    /* CA */ OP1(RETF, Iw),
    /* CB */ OP0(RETF),
    /* CC */ OP1(INT, 3),
    /* CD */ OP1(INT, Ib),
    /* CE */ OP0(INTO), /* i64 */
    /* CF */ OP0(IRET), /* IRET/D/Q */

    /* D0 */ OP2(_EXT2, Eb, 1),
    /* D1 */ OP2(_EXT2, Ev, 1),
    /* D2 */ OP2(_EXT2, Eb, CL),
    /* D3 */ OP2(_EXT2, Ev, CL),
    /* D4 */ OP1(AAM, Ib), /* i64 */
    /* D5 */ OP1(AAD, Ib), /* i64 */
    /* D6 */ OP_EMPTY,
    /* D7 */ OP0(XLAT), /* XLATB */
    /* D8-D15 */ OP_EMPTY_8, /* escape to x87 fpu */

    /* E0 */ OP1(LOOPNE, Jb), /* f64 */
    /* E1 */ OP1(LOOPE, Jb), /* f64 */
    /* E2 */ OP1(LOOP, Jb), /* f64 */
    /* E3 */ OP1(JCXZ, Jb), /* f64; JrCXZ */
    /* E4 */ OP2(IN, AL, Ib),
    /* E5 */ OP2(IN, eAX, Ib),
    /* E6 */ OP2(OUT, Ib, AL),
    /* E7 */ OP2(OUT, Ib, eAX),
    /* E8 */ OP1(CALL, Jz), /* f64 */
    /* E9 */ OP1(JMP, Jz), /* near, f64 */
    /* EA */ OP1(JMP, Ap), /* far, i64 */
    /* EB */ OP1(JMP, Jb), /* short, f64 */
    /* EC */ OP2(IN, AL, DX),
    /* ED */ OP2(IN, eAX, DX),
    /* EE */ OP2(OUT, DX, AL),
    /* EF */ OP2(OUT, DX, eAX),

    /* F0 */ OP_EMPTY, /* LOCK (prefix) */
    /* F1 */ OP_EMPTY,
    /* F2 */ OP_EMPTY, /* REPNE (prefix) */
    /* F3 */ OP_EMPTY, /* REPE (prefix) */
    /* F4 */ OP0(HLT),
    /* F5 */ OP0(CMC),
    /* F6 */ OP1(_EXT3, Eb),
    /* F7 */ OP1(_EXT3, Ev),
    /* F8 */ OP0(CLC),
    /* F9 */ OP0(STC),
    /* FA */ OP0(CLI),
    /* FB */ OP0(STI),
    /* FC */ OP0(CLD),
    /* FD */ OP0(STD),
    /* FE */ OP0(_EXT4), /* INC/DEC */
    /* FF */ OP0(_EXT5)  /* INC/DEC */
};

/**
 * Decodes instruction prefixes, and stores them in the instruction.
 * If one or more prefixes are found, returns the number of bytes consumed.
 * If no prefix is found, returns 0. 
 * If the instruction is invalid, returns -1.
 */
static int decode_prefix(const unsigned char *code, x86_insn_t *insn, const x86_options_t *opt)
{
    /* Prefix table, where prefix_grp[c] = the prefix group of byte c.
     * The group number can be from 1 to 5, whose meaning is as follows:
     *
     *   Group 1-4 : legacy group 1-4.
     *   Group 5: REX prefix (only available in 64-bit mode).
     *
     * At most one prefix from each group may be present in an instruction.
     * If a prefix is already present, it is an invalid instruction. If an
     * REX prefix is encountered, no more prefixes are read because an REX 
     * prefix is required to immediately preceed the opcode.
     */
    static const unsigned char prefix_grp[256] = 
    {
        /* 0 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 1 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 2 */  0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0,
        /* 3 */  0, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0, 0, 2, 0,
        /* 4 */  5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 
        /* 5 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 6 */  0, 0, 0, 0, 2, 2, 3, 4, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 7 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 8 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* 9 */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* A */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* B */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* C */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* D */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* E */  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        /* F */  1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    const unsigned char *p = code;
    for ( ; ; p++)
    {
        unsigned char c = *p;

        /* Find out which prefix group the byte belongs to. */
        unsigned char grp = prefix_grp[c];

        /* Finish if this byte is not a prefix. */
        if (grp == 0)
            break;

        /* Finish if this byte is REX prefix, but we're not in 64-bit mode. */
        if (grp == 5 && CPU_SIZE(opt) != OPR_64BIT)
            break;

        /* Make sure only one prefix from each group is present. */
        if (insn->prefix[grp - 1] != 0)
            return -1;

        /* Set the prefix in the instruction. */
        insn->prefix[grp - 1] = c;

        /* If this byte is REX prefix, we needn't check prefixes no more. */
        if (grp == 5)
        {
            p++;
            break;
        }
    }

    /* Return the number of bytes consumed. */
    return (p - code);
}

static x86_insn_spec_t
process_opcode_extension(
    x86_insn_spec_t spec,
    uint32_t opcode, 
    unsigned char modrm)
{
    int16_t op = SPEC_INSN(spec);
    int reg = REG(modrm);
    int mod = MOD(modrm);

    /* Remove the opcode part of 'spec' so that it can be merged. */
    spec = SPEC_OPERANDS(spec);

    if (op == I__EXT1)
    {
        static const x86_insn_spec_t map[8] =
        {
            OP0(ADD), OP0(OR),  OP0(ADC), OP0(SBB),
            OP0(AND), OP0(SUB), OP0(XOR), OP0(CMP)
        };
        return SPEC_MERGE(map[reg], spec);
    }

    if (op == I__EXT1A)
    {
        static const x86_insn_spec_t map[8] = { OP0(POP) };
        return SPEC_MERGE(map[reg], spec);
    }

    if (op == I__EXT2)
    {
        static const x86_insn_spec_t map[8] =
        {
            OP0(ROL), OP0(ROR), OP0(RCL), OP0(RCR),
            OP0(SHL), OP0(SHR), OP_EMPTY, OP0(SAR)
        };
        return SPEC_MERGE(map[reg], spec);
    }

    if (op == I__EXT3)
    {
        static const x86_insn_spec_t map_f6[8] =
        {
            OP2(TEST, Eb, Ib),
            OP_EMPTY,
            OP1(NOT,  Eb),
            OP1(NEG,  Eb),
            OP2(MUL,  Eb, AL),
            OP2(IMUL, Eb, AL),
            OP2(DIV,  Eb, AL),
            OP2(IDIV, Eb, AL)
        };
        static const x86_insn_spec_t map_f7[8] =
        {
            OP2(TEST, Ev, Iz),
            OP_EMPTY,
            OP1(NOT,  Ev),
            OP1(NEG,  Ev),
            OP2(MUL,  Ev, rAX),
            OP2(IMUL, Ev, rAX),
            OP2(DIV,  Ev, rAX),
            OP2(IDIV, Ev, rAX)
        };
        if (opcode == 0xF6)
            return map_f6[reg];
        else /* opcode == 0xF7 */
            return map_f7[reg];
    }

    if (op == I__EXT4)
    {
        static const x86_insn_spec_t map[8] = 
        {
            OP1(INC, Eb), OP1(DEC, Eb)
        };
        return map[reg];
    }

    if (op == I__EXT5)
    {
        static const x86_insn_spec_t map[8] = 
        {
            OP1(INC,  Eb), OP1(DEC,  Eb), OP1(CALLN, Ev), OP1(CALLF, Ep),
            OP1(JMPN, Ev), OP1(JMPF, Mp), OP1(PUSH,  Ev), OP_EMPTY
        };
        return map[reg];
    }

    if (op == I__EXT6)
    {
        static const x86_insn_spec_t map[8] = 
        {
            OP2(SLDT, Rv, Mw),
            OP2(STR, Rv, Mw),
            OP1(LLDT, Ew),
            OP1(LTR, Ew),
            OP1(VERR, Ew),
            OP1(VERW, Ew),
            OP_EMPTY,
            OP_EMPTY
        };
        return map[reg];
    }

    if (op == I__EXT11)
    {
        if (reg == 0)
        {
            if (opcode == 0xC6)
                return OP2(MOV, Eb, Ib);
            else if (opcode == 0xC7)
                return OP2(MOV, Ev, Iz);
        }
        else if (modrm == 0xF8)
        {
            if (opcode == 0xC6)
                return OP1(XABORT, Ib);
            else if (opcode == 0xC7)
                return OP1(XBEGIN, Jz);
        }
        return 0;
    }

    /* Invalid opcode extension. */
    return 0;
}

/* Decodes the opcode of an instruction and returns its encoding 
 * specification.
 */
static x86_insn_spec_t
decode_opcode(
    x86_insn_reader_t *rd,
    int cpu_size)        
{
    unsigned char c;
    x86_insn_spec_t spec;

    /* Process the first byte of the opcode. */
    c = read_byte(rd);
    mark_modrm(rd);
    spec = x86_opcode_map_1byte[c];
    
    /* Return the encoding spec if it is a valid instruction. */
    if (SPEC_INSN(spec) > 0)
        return spec;

    /* Process opcode extension if required. */
    if (SPEC_INSN(spec) < 0)
    {
        return process_opcode_extension(spec, c, read_modrm(rd));
    }

    return 0;
}

#define FILL_REG(_opr, _reg) \
    do { \
        x86_reg_t r = (_reg); \
        (_opr)->size = REG_SIZE(r); \
        (_opr)->type = OPR_REG; \
        (_opr)->val.reg = r; \
    } while (0)

#define FILL_MEM(_opr, _size, _segment, _base, _index, _scaling, _disp) \
    do { \
        (_opr)->size = (_size); \
        (_opr)->type = OPR_MEM; \
        (_opr)->val.mem.segment = (_segment); \
        (_opr)->val.mem.base = (_base); \
        (_opr)->val.mem.index = (_index); \
        (_opr)->val.mem.scaling = (_scaling); \
        (_opr)->val.mem.displacement = (_disp); \
    } while (0)

#define FILL_IMM(_opr, _size, _imm) \
    do { \
        (_opr)->size = (_size); \
        (_opr)->type = OPR_IMM; \
        (_opr)->val.imm = _imm; \
    } while (0)

#define FILL_REL(_opr, _size, _rel) \
    do { \
        (_opr)->size = (_size); \
        (_opr)->type = OPR_REL; \
        (_opr)->val.rel = _rel; \
    } while (0)

/* Converts byte register 0-7 from machine encoding to logical identifier. */
#define REG_CONVERT_BYTE(number) REG_MAKE(R_TYPE_GENERAL, (number) & 3, OPR_8BIT, (number) >> 2)

#if 0
struct x86_raw_insn_t
{
    uint32_t opcode;
    uint8_t  modrm;
    uint8_t  sib;
    uint32_t disp;
    uint32_t imm;
};
#endif

/* Decodes a memory (or optionally register) operand. A ModR/M byte follows
 * the opcode and specifies the operand. If reg_type is not zero, the operand
 * is allowed to be a register of the specified type. If the operand is a 
 * memory address, the address is computed from a segment register and any of
 * the following values: a base register, an index register, a scaling factor, 
 * and a displacement.
 *
 * The function returns non-zero if successful, or 0 if the instruction is
 * invalid.
 */
static int decode_memory_operand(
    x86_opr_t *opr,             /* decoded operand */
    x86_insn_reader_t *rd,      /* stream reader */
    int opr_size,               /* size of the register or operand */
    int reg_type,               /* if non-zero, type of the register */
    int cpu_size)               /* word-size of the cpu */
{
    unsigned char modrm = read_modrm(rd);

    if (cpu_size == OPR_16BIT)
    {
        /* Decode a register if MOD = (11). */
        if (MOD(modrm) == 3)
        {
            if (reg_type == 0) /* register not allowed */
                return 0;

            /* Interpret it as a register. Treat AH-DH specially. */
            if (reg_type == R_TYPE_GENERAL && opr_size == OPR_8BIT)
                FILL_REG(opr, REG_CONVERT_BYTE(RM(modrm)));
            else
                FILL_REG(opr, REG_MAKE(reg_type, RM(modrm), opr_size, 0));
            return 1;
        }

        /* Decode a direct memory address if MOD = (00) and RM = (110). */
        if (MOD(modrm) == 0 && RM(modrm) == 6) /* disp16 */
        {
            uint32_t disp = read_word(rd);
            FILL_MEM(opr, opr_size, R_DS, 0, 0, 0, disp);
            return 1;
        }

        /* Decode an indirect memory address XX[+YY][+disp]. */
        switch (RM(modrm))
        {
        case 0: /* [BX+SI] */
            FILL_MEM(opr, opr_size, R_DS, R_BX, R_SI, 1, 0);
            break;
        case 1: /* [BX+DI] */
            FILL_MEM(opr, opr_size, R_DS, R_BX, R_DI, 1, 0);
            break;
        case 2: /* [BP+SI] */
            FILL_MEM(opr, opr_size, R_SS, R_BP, R_SI, 1, 0);
            break;
        case 3: /* [BP+DI] */
            FILL_MEM(opr, opr_size, R_DS, R_BP, R_SI, 1, 0);
            break;
        case 4: /* [SI] */
            FILL_MEM(opr, opr_size, R_DS, R_SI, 0, 1, 0);
            break;
        case 5: /* [DI] */
            FILL_MEM(opr, opr_size, R_DS, R_DI, 0, 1, 0);
            break;
        case 6: /* [BP] */
            FILL_MEM(opr, opr_size, R_SS, R_BP, 0, 1, 0);
            break;
        case 7: /* [BX] */
            FILL_MEM(opr, opr_size, R_DS, R_BX, 0, 1, 0);
            break;
        }
        if (MOD(modrm) == 1) /* disp8 */
            opr->val.mem.displacement = read_byte(rd);
        else if (MOD(modrm) == 2) /* disp16 */
            opr->val.mem.displacement = read_word(rd);
        return 1;
    }
    else if (cpu_size == OPR_32BIT)
    {

    }
    return 0; /* should not reach here */
}

/* Decode an operand from an instruction. If successful, returns non-zero.
 * If failed, returns zero.
 */
static int decode_operand(
    x86_opr_t *opr,             /* decoded operand */
    x86_insn_reader_t *rd,      /* stream reader */
    int spec,                   /* operand encoding specification */
    const x86_options_t *opt)   /* options */
{
    int reg = R_NONE;
    unsigned char modrm;
    /* uint32_t imm; */
    int cpu_size = CPU_SIZE(opt);
    /* int opr_size; */

    /* Decode specific registers. */
    if (spec >= 0x90)
    {
        int reg;
        int number = spec & 0xf;
        switch (spec & 0xf0)
        {
        case O_XS: /* segment register */
            reg = REG_MAKE(R_TYPE_SEGMENT, number, OPR_16BIT, 0);
            break;
        case O_XL: /* low byte register */
            if (number < 4)
                reg = REG_MAKE(R_TYPE_GENERAL, number, OPR_8BIT, 0);
            else
                reg = REG_MAKE(R_TYPE_GENERAL, number - 4, OPR_8BIT, R_OFFSET_HIBYTE);
            break;
#if 0
        case O_XH: /* high byte register */    
            break;
#endif
        case O_XX: /* 16-bit GPR */
            reg = REG_MAKE(R_TYPE_GENERAL, number, OPR_16BIT, 0);
            break;
        case O_eXX: /* 16-bit or 32-bit */
            reg = REG_MAKE(R_TYPE_GENERAL, number, 
                (cpu_size == OPR_16BIT)? OPR_16BIT : OPR_32BIT, 0);
            break;
        case O_rXX: /* 16-bit, 32-bit, or 64-bit */
            reg = REG_MAKE(R_TYPE_GENERAL, number, cpu_size, 0);
            break;
        default:
            return 0;
        }
        FILL_REG(opr, reg);
        return 1;
    }

    /* Decode immediates. */
    if (spec >= 0x80)
    {
        opr->size = OPR_8BIT;
        opr->type = OPR_IMM;
        opr->val.imm = (spec - O_n);
        return 1;
    }

    /* Decode regular operands. */
    switch (spec)
    {
    case O_Gb:
        /* REG(modrm) selects byte-size GPR. */
        /* TBD: check AH-DH */
        modrm = read_modrm(rd);
        FILL_REG(opr, REG_CONVERT_BYTE(REG(modrm)));
        break;

    case O_Gv:
        /* REG(modrm) selects GPR of native size (16, 32, or 64 bit) */
        modrm = read_modrm(rd);
        FILL_REG(opr, REG_MAKE(R_TYPE_GENERAL, REG(modrm), cpu_size, 0));
        break;

    case O_Gw:
        /* REG(modrm) selects word-size GPR. */
        modrm = read_modrm(rd);
        reg = REG_MAKE(R_TYPE_GENERAL, REG(modrm), OPR_16BIT, 0);
        FILL_REG(opr, reg);
        break;

    case O_Gz:
        /* REG(modrm) selects word-size GPR for 16-bit, dword-size GPR for
         * 32 or 64 bit. 
         */
        modrm = read_modrm(rd);
        reg = REG_MAKE(R_TYPE_GENERAL, REG(modrm), 
                CPU_SIZE(opt) == OPR_16BIT ? OPR_16BIT : OPR_32BIT, 0);
        FILL_REG(opr, reg);
        break;

    case O_Eb:
        /* The operand is either a general-purpose register or a memory
         * address, encoded by ModR/M + SIB + displacement. The size of 
         * the operand is byte.
         */
        return decode_memory_operand(opr, rd, OPR_8BIT, R_TYPE_GENERAL, cpu_size);

    case O_Ev:
        /* The operand is either a general-purpose register or a memory
         * address, encoded by ModR/M + SIB + displacement. The size of 
         * the operand is the native word size of the CPU.
         */
        return decode_memory_operand(opr, rd, cpu_size, R_TYPE_GENERAL, cpu_size);

    case O_Ew:
        /* The operand is either a general-purpose register or a memory
         * address, encoded by ModR/M + SIB + displacement. The size of 
         * the operand is word.
         */
        return decode_memory_operand(opr, rd, OPR_16BIT, R_TYPE_GENERAL, cpu_size);

    case O_Ib: /* byte immediate */
        FILL_IMM(opr, OPR_8BIT, read_byte(rd));
        break;

    case O_Iv: /* native size immediate */
        FILL_IMM(opr, cpu_size, read_imm(rd, cpu_size));
        break;

    case O_Iw: /* word immediate */
        FILL_IMM(opr, OPR_16BIT, read_word(rd));
        break;

    case O_Iz: /* native or dword, whichever is smaller */
        if (cpu_size == OPR_16BIT)
            FILL_IMM(opr, OPR_16BIT, read_word(rd));
        else
            FILL_IMM(opr, OPR_32BIT, read_dword(rd));
        break;

    case O_Jb: /* immediate encodes relative offset (byte) */
        FILL_REL(opr, OPR_8BIT, read_byte(rd));
        break;

    case O_Jz: /* immediate encodes relative offset (word or dword) */
        if (cpu_size == OPR_16BIT)
            FILL_REL(opr, OPR_16BIT, read_word(rd));
        else
            FILL_REL(opr, OPR_32BIT, read_dword(rd));
        break;

    case O_Sw: /* REG(modrm) selects segment register */
        modrm = read_modrm(rd);
        reg = REG_MAKE(R_TYPE_SEGMENT, REG(modrm), OPR_16BIT, 0);
        FILL_REG(opr, reg);
        break;

    case O_Ob: /* no ModR/M byte; absolute memory address in disp as
                * 16-bit or 32-bit near ptr
                */
        if (cpu_size == OPR_16BIT)
            FILL_MEM(opr, OPR_8BIT, R_DS, R_NONE, R_NONE, 1, read_word(rd));
        else
            FILL_MEM(opr, OPR_8BIT, R_DS, R_NONE, R_NONE, 1, read_dword(rd));
        break;

    case O_Ov: /* no ModR/M byte; absolute memory address (native word)
                * encoded in displacement of either word or dword.
                */
        /* TBD: operand size prefix */
        if (cpu_size == OPR_16BIT)
            FILL_MEM(opr, cpu_size, R_DS, R_NONE, R_NONE, 1, read_word(rd));
        else
            FILL_MEM(opr, cpu_size, R_DS, R_NONE, R_NONE, 1, read_dword(rd));
        break;

    case O_Mp: /* The ModR/M byte must refer to memory of seg:ptr */
        return decode_memory_operand(opr, rd, cpu_size, 0, cpu_size);

    case O_Ap: /* No ModR/M byte; address encoded in imm in the form of
                * seg:ptr */
        FILL_IMM(opr, cpu_size, read_imm(rd, cpu_size));    /* ptr */
        FILL_IMM(opr, OPR_16BIT, read_word(rd));            /* seg */
        break;

    default:
        return 0; /* invalid specification */
    }
    return 1;
}

int x86_decode(
    const unsigned char *code_begin,
    const unsigned char *code_end,
    x86_insn_t *insn, 
    const x86_options_t *opt)
{
    const unsigned char *p = code_begin;
    int count, i;
    x86_insn_reader_t rd;
    x86_insn_spec_t spec;

    /* Clear instruction. */
    memset(insn, 0, sizeof(x86_insn_t));

    /* Initialize reader. */
    init_reader(&rd, code_begin, code_end);

    /* Decode prefixes. */
    count = decode_prefix(p, insn, opt);
    if (count < 0)
        return -1;
    p += count;
    rd.opcode += count;
    rd.modrm += count;
    rd.end += count;

    /* Decode the opcode and get encoding specification. */
    spec = decode_opcode(&rd, CPU_SIZE(opt));
    if (SPEC_INSN(spec) == 0)
        return -1;
    insn->op = SPEC_INSN(spec);

    /* Decode operands. */
    for (i = 0; i < MAX_OPERANDS; i++)
    {
        int opr_spec = SPEC_OPERAND(spec, i);
        if (opr_spec == 0) /* no more operands */
            break;

        if (!decode_operand(&insn->oprs[i], &rd, opr_spec, opt)) /* failed */
            return -1;
    }

    /* Returns the number of bytes consumed. */
    return (rd.end - rd.prefix);
}
