/* format.c -- formats an instruction as a string. */

#include "x86_codec.h"

#include <string.h>
#include <stdio.h>

static const char *insn_str[] = 
{
    "NONE",
#define I(x) #x ,
#include "x86_mnemonic.inc"
#undef I
    "XXXX"
};

static const char *getRegString(x86_reg_t reg)
{
#define CASE_REG(r) case R_##r : return #r 
    switch (reg)
    {
        CASE_REG(NONE);

        /* byte registers */
        CASE_REG(AH);
        CASE_REG(CH);
        CASE_REG(DH);
        CASE_REG(BH);
        CASE_REG(AL);
        CASE_REG(CL);
        CASE_REG(DL);
        CASE_REG(BL);
        CASE_REG(SPL);
        CASE_REG(BPL);
        CASE_REG(SIL);
        CASE_REG(DIL);
        CASE_REG(R8L);
        CASE_REG(R9L);
        CASE_REG(R10L);
        CASE_REG(R11L);
        CASE_REG(R12L);
        CASE_REG(R13L);
        CASE_REG(R14L);
        CASE_REG(R15L);

        /* word registers */
        CASE_REG(AX);
        CASE_REG(CX);
        CASE_REG(DX);
        CASE_REG(BX);
        CASE_REG(SP);
        CASE_REG(BP);
        CASE_REG(SI);
        CASE_REG(DI);
        CASE_REG(R8W);
        CASE_REG(R9W);
        CASE_REG(R10W);
        CASE_REG(R11W);
        CASE_REG(R12W);
        CASE_REG(R13W);
        CASE_REG(R14W);
        CASE_REG(R15W);
    
        /* dword registers */
        CASE_REG(EAX);
        CASE_REG(ECX);
        CASE_REG(EDX);
        CASE_REG(EBX);
        CASE_REG(ESP);
        CASE_REG(EBP);
        CASE_REG(ESI);
        CASE_REG(EDI);
        CASE_REG(R8D);
        CASE_REG(R9D);
        CASE_REG(R10D);
        CASE_REG(R11D);
        CASE_REG(R12D);
        CASE_REG(R13D);
        CASE_REG(R14D);
        CASE_REG(R15D);

        /* qword registers */
        CASE_REG(RAX);
        CASE_REG(RCX);
        CASE_REG(RDX);
        CASE_REG(RBX);
        CASE_REG(RSP);
        CASE_REG(RBP);
        CASE_REG(RSI);
        CASE_REG(RDI);
        CASE_REG(R8);
        CASE_REG(R9);
        CASE_REG(R10);
        CASE_REG(R11);
        CASE_REG(R12);
        CASE_REG(R13);
        CASE_REG(R14);
        CASE_REG(R15);

        /* segment registers */
        CASE_REG(ES);
        CASE_REG(CS);
        CASE_REG(SS);
        CASE_REG(DS);
        CASE_REG(FS);
        CASE_REG(GS);
 
        /* Control registers (eee). See Volume 2, Appendix B, Table B-9. */
        CASE_REG(CR0);
        CASE_REG(CR2);
        CASE_REG(CR3);
        CASE_REG(CR4);

        /* Debug registers (eee). See Volume 2, Appendix B, Table B-9. */
        CASE_REG(DR0);
        CASE_REG(DR1);
        CASE_REG(DR2);
        CASE_REG(DR3);
        CASE_REG(DR6);
        CASE_REG(DR7);

        /* MMX registers. */
        CASE_REG(MM0);
        CASE_REG(MM1);
        CASE_REG(MM2);
        CASE_REG(MM3);
        CASE_REG(MM4);
        CASE_REG(MM5);
        CASE_REG(MM6);
        CASE_REG(MM7);

        /* XMM registers. */
        CASE_REG(XMM0);
        CASE_REG(XMM1);
        CASE_REG(XMM2);
        CASE_REG(XMM3);
        CASE_REG(XMM4);
        CASE_REG(XMM5);
        CASE_REG(XMM6);
        CASE_REG(XMM7);
        CASE_REG(XMM8);
        CASE_REG(XMM9);
        CASE_REG(XMM10);
        CASE_REG(XMM11);
        CASE_REG(XMM12);
        CASE_REG(XMM13);
        CASE_REG(XMM14);
        CASE_REG(XMM15);

        /* Special registers. */
        CASE_REG(IP);
        CASE_REG(FLAGS);
        CASE_REG(EIP);
        CASE_REG(EFLAGS);
        CASE_REG(MXCSR);
    }
    return "INVALID";
#undef CASE_REG
}

static char *
copy_string_and_change_case(const char *src, char *dest, x86_fmt_t fmt)
{
    /* Turn to lower case if necessary. */
    for (; *src; dest++, src++)
    {
        if (*src >= 'A' && *src <= 'Z')
            *dest = *src - 'A' + 'a';
        else
            *dest = *src;
    }
    return dest;
}

static char *
format_imm(uint32_t imm, char *p, x86_fmt_t fmt)
{
    int i;

    /* Encode in decimal if it's a single digit. */
    if (imm < 10)
    {
        *p++ = '0' + imm;
        return p;
    }

    /* Prepend with 0 if the first character is alpha. */
    if (imm & 0x88888888UL)
        *p++ = '0';

    /* Find the first non-zero nibble. */
    for (i = 28; i >= 0; i -= 4)
    {
        if (imm >> i)
            break;
    }

    /* Format each hexidecimal nibble. */
    for (; i >= 0; i -= 4)
    {
        int d = (imm >> i) & 0xf;
        *p++ = (d < 10)? ('0' + d) : ('a' + d - 10);
    }

    /* Append hexidecimal mark. */
    *p++ = 'h';
    return p;
}

static char *
format_rel(int32_t rel, char *p, x86_fmt_t fmt)
{
    if (rel >= 0)
        *p++ = '+';
    sprintf(p, "%d", rel);
    p += strlen(p);
    return p;
}

static char *
format_reg(x86_reg_t reg, char *p, x86_fmt_t fmt)
{
    return copy_string_and_change_case(getRegString(reg), p, fmt);
}

static char *
format_mem(const x86_opr_t *opr, char *p, x86_fmt_t fmt)
{
    const char *prefix = 
        (opr->size == OPR_8BIT)? "byte" :
        (opr->size == OPR_16BIT)? "word" :
        (opr->size == OPR_32BIT)? "dword" :
        (opr->size == OPR_64BIT)? "qword" :
        (opr->size == OPR_128BIT)? "dqword" : "";
    const x86_mem_t *mem = &opr->val.mem;

    p = copy_string_and_change_case(prefix, p, fmt);
    p = copy_string_and_change_case(" PTR ", p, fmt);
    p = copy_string_and_change_case(getRegString(mem->segment), p, fmt);
    *p++ = ':';
    *p++ = '[';
    if (mem->base)
    {
        p = copy_string_and_change_case(getRegString(mem->base), p, fmt);
        if (mem->index)
        {
            *p++ = '+';
            p = copy_string_and_change_case(getRegString(mem->index), p, fmt);
            if (mem->scaling)
            {
                *p++ = '*';
                p = format_imm(mem->scaling, p, fmt);
            }
        }
    }
    if (mem->displacement || mem->base == R_NONE)
    {
        if (mem->base)
            *p++ = '+';
        p = format_imm(mem->displacement, p, fmt);
    }
    *p++ = ']';
    return p;
}

static char *
format_operand(const x86_opr_t *opr, char *p, x86_fmt_t fmt)
{
    switch (opr->type)
    {
    case OPR_REG:
        return format_reg(opr->val.reg, p, fmt);
    case OPR_MEM:
        return format_mem(opr, p, fmt);
    case OPR_IMM:
        return format_imm(opr->val.imm, p, fmt);
    case OPR_REL:
        return format_rel(opr->val.rel, p, fmt);
    default:
        return p;
    }
}

void x86_format(const x86_insn_t *insn, char buffer[256], x86_fmt_t fmt)
{
    const int N = sizeof(insn_str) / sizeof(insn_str[0]);
    char *p;
    int i;

    buffer[0] = 0;

    /* Format mnemonic. */
    if (!(insn->op >= 0 && insn->op < N))
        return;

    /* Turn to lower case if necessary. */
    p = copy_string_and_change_case(insn_str[insn->op], buffer, fmt);

    /* Format operands. */
    for (i = 0; i < MAX_OPERANDS; i++)
    {
        /* Stop if no more operands. */
        if (insn->oprs[i].type == OPR_NONE)
            break;

        /* Append , and space to delimit operands. */
        if (i > 0)
            *p++ = ',';
        *p++ = ' ';

        /* Format operand. */
        p = format_operand(&insn->oprs[i], p, fmt);
    }

    /* NUL-terminate the string. */
    *p = 0;
}