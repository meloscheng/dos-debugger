#include "disassembler.h"
#include "x86codec/x86_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include "vector.h"

#define FARPTR_TO_OFFSET(p) (((uint32_t)(p).seg << 4) + (uint32_t)(p).off)

const char * dasm_xref_type_string(dasm_xref_type type)
{
#define CASE(x) case x : return #x 
    switch (type)
    {
        CASE(XREF_USER_SPECIFIED);
        CASE(XREF_FUNCTION_CALL);
        CASE(XREF_CONDITIONAL_JUMP);
        CASE(XREF_UNCONDITIONAL_JUMP);
        CASE(XREF_INDIRECT_JUMP);
        /* CASE(XREF_RETURN_FROM_CALL); */
        /* CASE(XREF_RETURN_FROM_INTERRUPT); */
    default:
        return "XREF_UNKNOWN";
    }
#undef CASE
}

typedef struct dasm_jump_table_t
{
    dasm_farptr_t insn_pos; /* location of the jump instruction */
    dasm_farptr_t start;    /* location of the start of the jump table */
    dasm_farptr_t current;  /* location of the next jump entry to process */
} dasm_jump_table_t;

/* Represents an X86 disassembler. */
typedef struct x86_dasm_t
{
    const unsigned char *image;
    size_t image_size;
    byte_attr_t attr[0x1000000]; /* 1MB bytes */
    VECTOR(dasm_xref_t) entry_points; /* dasm_code_block_t code_blocks */
    /* however, it is not exactly a block; it is more like an entry point */
    VECTOR(dasm_jump_table_t) jump_tables;
} x86_dasm_t;

byte_attr_t dasm_get_byte_attr(x86_dasm_t *d, uint32_t offset)
{
    return d->attr[offset];
}

x86_dasm_t * dasm_create(const unsigned char *image, size_t size)
{
    x86_dasm_t *d;
    d = (x86_dasm_t *)malloc(sizeof(x86_dasm_t));
    if (d == NULL)
        return NULL;
    d->image = image;
    d->image_size = size;

    /* Initialize all bytes in the image to unknown status. */
    memset(d->attr, 0, d->image_size);

    VECTOR_CREATE(d->entry_points, dasm_xref_t);
    VECTOR_CREATE(d->jump_tables, dasm_jump_table_t);
    return d;
}

void dasm_destroy(x86_dasm_t *d)
{
    if (d)
    {
        VECTOR_DESTROY(d->entry_points);
        VECTOR_DESTROY(d->jump_tables);
        free(d);
    }
}

#define ST_OK                0
#define ST_ALREADY_ANALYZED -1
#define ST_UNEXPECTED_DATA  -2
#define ST_UNEXPECTED_CODE  -3
#define ST_BAD_INSTRUCTION  -4

/* Try decode an instruction from the byte range starting at offset _start_.
 * If successful, stores the instruction in _insn_ and returns the number
 * of bytes consumed. Otherwise returns one of the following error codes:
 *
 * ST_ALREADY_ANALYZED 
 *      The byte is already analyzed (as code).
 * ST_BAD_INSTRUCTION  
 *      The bytes at the given range do not form a valid instruction.
 * ST_UNEXPECTED_DATA  
 *      The byte, or an instruction if decoded, runs into bytes previously 
 *      analyzed as data.
 * ST_UNEXPECTED_CODE  
 *      The byte, or an instruction if decoded, runs into bytes previously 
 *      analyzed as code. However, the byte itself is not previously analyzed
 *      to be the start of an instruction.
 */
int decode_instruction(x86_dasm_t *d, dasm_farptr_t start, x86_insn_t *insn)
{
    size_t b = FARPTR_TO_OFFSET(start);
    int count, i;
    x86_options_t opt = { OPR_16BIT };

    /* If the byte to analyze is already interpreted as data, return a 
     * conflict status.
     */
    if ((d->attr[b] & ATTR_TYPE) == TYPE_DATA)
        return ST_UNEXPECTED_DATA;

    /* If this byte to analyze is already interpreted as code, check that
     * it was treated as the first byte of an instruction. Otherwise, return
     * a conflict status.
     */
    if ((d->attr[b] & ATTR_TYPE) == TYPE_CODE)
    {
        if (d->attr[b] & ATTR_BOUNDARY)
            return ST_ALREADY_ANALYZED;
        else
            return ST_UNEXPECTED_CODE;
    }

    /* Decode an instruction at this location. */
    count = x86_decode(d->image + b, d->image + d->image_size, insn, &opt);
    if (count <= 0)
        return ST_BAD_INSTRUCTION;

    /* Check that the entire instruction covers unprocessed area. If any byte
     * in the area is already processed, return an error.
     */
    for (i = 1; i < count; i++)
    {
        if (d->attr[b + i] & ATTR_PROCESSED)
        {
            return (d->attr[b + i] & ATTR_TYPE) == TYPE_CODE ?
                ST_UNEXPECTED_CODE : ST_UNEXPECTED_DATA;
        }
    }

    /* Mark the bytes covered by the instruction as code. */
    for (i = 0; i < count; i++)
    {
        d->attr[b + i] &= ~ATTR_TYPE;
        d->attr[b + i] |= TYPE_CODE;
        d->attr[b + i] &= ~ATTR_BOUNDARY;
    }
    d->attr[b] |= ATTR_BOUNDARY;
            
    /* Return the number of bytes consumed. */
    return count;
}

#define FLOW_WRAPPED        -2
#define FLOW_FAILED         -1
#define FLOW_CONTINUE       0
#define FLOW_FINISH_BLOCK   1   
#define FLOW_DYNAMIC_JUMP   2
#define FLOW_DYNAMIC_CALL   3

static dasm_farptr_t increment_farptr(dasm_farptr_t p, uint16_t increment)
{
    dasm_farptr_t q;
    q.seg = p.seg;
    q.off = p.off + increment;
    return q;
}

/* Analyze an instruction decoded from offset _start_ for _count_ bytes.
 * TBD: address wrapping if IP is above 0xFFFF is not handled. It should be.
 */
int analyze_flow_instruction(x86_dasm_t *d, dasm_farptr_t start, size_t count, x86_insn_t *insn)
{
    int op = insn->op;

    /* If this is an unconditional JMP instruction, push the jump target to
     * the queue and finish this block.
     */
    if (op == I_JMP || op == I_JMPN)
    {
        if (insn->oprs[0].type == OPR_REL) /* near jump to relative address */
        {
            dasm_xref_t xref;
            xref.source = start;
            xref.target = increment_farptr(start, count + insn->oprs[0].val.rel);
            xref.type = XREF_UNCONDITIONAL_JUMP;
            VECTOR_PUSH(d->entry_points, xref);
            return FLOW_FINISH_BLOCK;
        }
        if (insn->oprs[0].type == OPR_PTR) /* far jump to absolute address */
        {
            dasm_xref_t xref;
            xref.source = start;
            xref.target.seg = insn->oprs[0].val.ptr.seg;
            xref.target.off = (uint16_t)insn->oprs[0].val.ptr.off;
            xref.type = XREF_UNCONDITIONAL_JUMP;
            VECTOR_PUSH(d->entry_points, xref);
            return FLOW_FINISH_BLOCK;
        }

        /* Process near jump table. We recognize a jump table heuristically
         * if the instruction is of the form:
         *
         *   jmpn word ptr cs:[bx+3782h] 
         *
         * where bx may be replaced by another register and 3782h must be
         * the address immediately following this instruction. Also, the CS
         * prefix is mandatory.
         *
         * Note that an ill-formed executable may create a jump table not
         * conforming to the above rules, or create a non-jump table that
         * conforms to the above rules. We are not ready to deal with that
         * for now.
         */
        if (insn->oprs[0].type == OPR_MEM &&
            insn->oprs[0].size == OPR_16BIT &&
            insn->oprs[0].val.mem.segment == R_CS &&
            insn->oprs[0].val.mem.base != R_NONE &&
            insn->oprs[0].val.mem.index == R_NONE &&
            insn->oprs[0].val.mem.displacement == start.off + count)
        {
            dasm_jump_table_t table;
            table.insn_pos = start;
            table.start = increment_farptr(start, count);
            table.current = table.start;
            VECTOR_PUSH(d->jump_tables, table);
            return FLOW_FINISH_BLOCK;
        }
        return FLOW_DYNAMIC_JUMP;
    }

    /* If this is a RET instruction, finish the current block. */
    if (op == I_RETN || op == I_RETF)
    {
        return FLOW_FINISH_BLOCK;
    }

    /* If this is a CALL instruction, push the call target to the queue and
     * finish this block.
     *
     * Note: We need to know whether the subroutine being called will ever
     * return. For the moment we assume that it will return. 
     */
    if (op == I_CALL || op == I_CALLF)
    {
        if (insn->oprs[0].type == OPR_REL)
        {
            dasm_xref_t xref;
            xref.source = start;
            xref.target = increment_farptr(start, count + insn->oprs[0].val.rel);
            xref.type = XREF_FUNCTION_CALL;
            VECTOR_PUSH(d->entry_points, xref);
            return FLOW_CONTINUE;
        }
        if (insn->oprs[0].type == OPR_PTR)
        {
            dasm_xref_t xref;
            xref.source = start;
            xref.target.seg = insn->oprs[0].val.ptr.seg;
            xref.target.off = (uint16_t)insn->oprs[0].val.ptr.off;
            xref.type = XREF_FUNCTION_CALL;
            VECTOR_PUSH(d->entry_points, xref);
            return FLOW_CONTINUE;
        }
        return FLOW_DYNAMIC_CALL;
    }
        
    /* If this is a Jcc/JCXZ instruction, push the jump target to the queue, 
     * and follow the flow assuming no jump.
     *
     * Note: We assume that "no jump" is a reachable branch. If the code is
     * ill-formed such that the "no jump" branch will never be executed, the
     * analysis may not work correctly.
     */
    switch (op)
    {
    case I_JO:
    case I_JNO:
    case I_JB:
    case I_JNB:
    case I_JE:
    case I_JNE:
    case I_JBE:
    case I_JNBE:
    case I_JS:
    case I_JNS:
    case I_JP:
    case I_JNP:
    case I_JL:
    case I_JNL:
    case I_JLE:
    case I_JNLE:
    case I_JCXZ:
        if (insn->oprs[0].type == OPR_REL) /* jump to relative position */
        {
            dasm_xref_t xref;
            xref.source = start;
            xref.target = increment_farptr(start, count + insn->oprs[0].val.rel);
            xref.type = XREF_CONDITIONAL_JUMP;
            VECTOR_PUSH(d->entry_points, xref);
            return FLOW_CONTINUE;
        }
        /* A valid Jcc instruction must jump to relative address. If not,
         * the instruction is malformed.
         */
        return FLOW_FAILED;
    }

    /* This is not a flow-control instruction, so continue as usual. */
    return FLOW_CONTINUE;
}

/* Print statistics about the number of bytes analyzed. */
void dasm_stat(x86_dasm_t *d)
{
    size_t b;
    size_t total = d->image_size, code = 0, data = 0, insn = 0;

    for (b = 0; b < total; b++)
    {
        if ((d->attr[b] & ATTR_TYPE) == TYPE_CODE)
        {
            ++code;
            if (d->attr[b] & ATTR_BOUNDARY)
                ++insn;
        }
        else if ((d->attr[b] & ATTR_TYPE) == TYPE_DATA)
            ++data;
    }

    fprintf(stderr, "Image size: %d bytes\n", total);
    fprintf(stderr, "Code size : %d bytes\n", code);
    fprintf(stderr, "Data size : %d bytes\n", data);
    fprintf(stderr, "# Instructions: %d\n", insn);

    fprintf(stderr, "Jump tables: %d\n", VECTOR_SIZE(d->jump_tables));
}

static int verbose = 0;

/* Analyze the code block starting at location _start_ recursively. 
 * Return one of the following status codes:
 *
 * FLOW_CONTINUE
 *     The block was successfully analyzed.
 * FLOW_FINISH_BLOCK
 *     The block was already analyzed and nothing was done.
 */
void analyze_code_block(x86_dasm_t *d, dasm_xref_t entry)
{
    /* Maintain a list of pending code entry points to analyze. At the 
     * beginning, there is only one entry point, which is _start_.
     * As we encounter branch instructions (JMP, CALL, or Jcc) on the way, 
     * we push the target addresses to the queue of entry points, so 
     * that they can be analyzed later.
     */
    size_t i = VECTOR_SIZE(d->entry_points);

    /* Push the entry to the entry list. */
    VECTOR_PUSH(d->entry_points, entry);

    /* Decode the instruction at p. */
    for ( ; i < VECTOR_SIZE(d->entry_points); i++)
    {
        dasm_farptr_t pos = VECTOR_AT(d->entry_points, i).target;
        dasm_farptr_t from = VECTOR_AT(d->entry_points, i).source;

        if (verbose)
        {
            printf("%04X:%04X  ; -- %s FROM %04X:%04X --\n", 
                pos.seg, pos.off, 
                dasm_xref_type_string(VECTOR_AT(d->entry_points, i).type),
                from.seg, from.off);
        }

        /* Keep decoding instructions starting from this location until
         * we encounter end-of-input, analyzed code/data, or any of the
         * jump instructions: RET/IRET/JMP/HLT/CALL
         */
        while (1)
        {
            x86_insn_t insn;
            int ret, count;
            char text[256];

            /* Decode an instruction at this location. */
            ret = decode_instruction(d, pos, &insn);
            if (ret == ST_ALREADY_ANALYZED)
            {
                if (verbose)
                    printf("Already analyzed.\n");
                break;
            }
            if (ret == ST_UNEXPECTED_DATA)
            {
                printf("Jump into data!\n");
                break;
            }
            if (ret == ST_UNEXPECTED_CODE)
            {
                fprintf(stderr, "%04X:%04X  %s\n", pos.seg, pos.off, 
                    "Jump into the middle of code!");
                break;
            }
            if (ret == ST_BAD_INSTRUCTION)
            {
                printf("Bad instruction!\n");
                break;
            }

            /* Debug only: display the instruction in assembly. */
            x86_format(&insn, text, X86_FMT_LOWER|X86_FMT_INTEL);
            if (verbose)
                printf("%04X:%04X  %s\n", pos.seg, pos.off, text);

            /* Analyse any flow-control instruction. */
            count = ret;
            ret = analyze_flow_instruction(d, pos, count, &insn);
            if (ret == FLOW_FINISH_BLOCK)
            {
                break;
            }
            if (ret == FLOW_DYNAMIC_JUMP)
            {
                fprintf(stderr, "%04X:%04X  %-32s ; Dynamic analysis required\n",
                    pos.seg, pos.off, text);
                break;
            }
            if (ret == FLOW_DYNAMIC_CALL)
            {
                fprintf(stderr, "%04X:%04X  %-32s ; Dynamic analysis required\n",
                    pos.seg, pos.off, text);
                break;
            }
            if (ret == FLOW_FAILED)
            {
                fprintf(stderr, "%04X:%04X  %s\n", pos.seg, pos.off, 
                    "Flow analysis failed");
                break;
            }

            /* Advance the byte pointer. Note: the IP may wrap around 0xFFFF 
             * if pos.off + count > 0xFFFF. This is probably not intended but
             * technically allowed. So we allow for this for the moment.
             */
            pos.off += count;
        }

        if (verbose)
            printf("\n");
    }
}

static int compare_xrefs_by_target_and_source(const dasm_xref_t *a, const dasm_xref_t *b)
{
    int cmp = (int)FARPTR_TO_OFFSET(a->target) - (int)FARPTR_TO_OFFSET(b->target);
    if (cmp == 0)
        cmp = (int)FARPTR_TO_OFFSET(a->source) - (int)FARPTR_TO_OFFSET(b->source);
    return cmp;
}

static int compare_xrefs_by_target(const dasm_xref_t *a, const dasm_xref_t *b)
{
    return (int)FARPTR_TO_OFFSET(a->target) - (int)FARPTR_TO_OFFSET(b->target);
}

void dasm_analyze(x86_dasm_t *d, dasm_farptr_t start)
{
    dasm_xref_t entry;
    size_t i = VECTOR_SIZE(d->jump_tables);

    /* Create an entry point using the user-supplied starting offset. */
    entry.target = start;
    entry.source.seg = -1;
    entry.source.off = -1;
    entry.type = XREF_USER_SPECIFIED;
    
    /* Analyze the code block specified by the user. */
    analyze_code_block(d, entry);

#if 0
    fprintf(stderr, "\n-- Statistics after initial analysis --\n");
    dasm_stat(d);
#endif

    /* Analyze any jump tables encountered in the above analysis. Since we
     * may encounter more jump tables on the way, we do this recursively
     * until there are no more jump tables.
     */
    for ( ; i < VECTOR_SIZE(d->jump_tables); i++)
    {
        /* Analyze each entry in the jump table by assuming that it contains
         * the address to a code block. Note that this is a rather
         * opportunistic assumption -- it is fairly easy to construct a jump
         * table that violates this logic. Nevertheless, for the moment we 
         * will assume that the code is "well-formed".
         */
        dasm_farptr_t insn_pos = VECTOR_AT(d->jump_tables, i).insn_pos;
        uint32_t table_offset = FARPTR_TO_OFFSET(VECTOR_AT(d->jump_tables, i).start);
        uint32_t entry_offset = table_offset;
        while (!(d->attr[entry_offset] & ATTR_PROCESSED) && 
             !(d->attr[entry_offset+1] & ATTR_PROCESSED))
        {
            uint16_t target = (uint16_t)d->image[entry_offset] | 
                ((uint16_t)d->image[entry_offset+1] << 8);

            /* Mark this entry as data. */
            d->attr[entry_offset] &= ~ATTR_TYPE;
            d->attr[entry_offset] |= TYPE_DATA;
            d->attr[entry_offset] |= ATTR_BOUNDARY;

            d->attr[entry_offset+1] &= ~ATTR_TYPE;
            d->attr[entry_offset+1] |= TYPE_DATA;
            d->attr[entry_offset+1] &= ~ATTR_BOUNDARY;

            entry.target.seg = insn_pos.seg;
            entry.target.off = target;
            entry.source = insn_pos;
            entry.type = XREF_INDIRECT_JUMP;

#if 0
            fprintf(stderr, "Processing jump entry %d, target %04X:%04X\n",
                (entry_offset - table_offset) / 2, 
                entry.start.seg, entry.start.off);
#endif

            analyze_code_block(d, entry);

            /* Advance to the next jump entry. Each entry takes 2 bytes/ */
            entry_offset += 2;
        }
    }

    /* Sort the XREFs built from the above analyses by target address. 
     * After this is done, the client can easily list the disassembled
     * instructions with xrefs sequentially in physical order.
     */
    VECTOR_QSORT(d->entry_points, compare_xrefs_by_target_and_source);

#if 0
        /* Output address. */
        printf("0000:%04X  ", (unsigned int)(p - code));

        /* Output binary code. */
        for (int i = 0; i < 8; i++)
        {
            if (i < count)
                printf("%02x ", p[i]);
            else
            {
                std::cout << "   ";
            }
        }

        char text[256];
        x86_format(&insn, text, X86_FMT_INTEL|X86_FMT_LOWER);
        std::cout << text << std::endl;
        if (text[0] == '*')
            __debugbreak();
        else
            p += count;
#endif
}

/* Returns the next xref that refers to the given target address. */
const dasm_xref_t * 
dasm_enum_xrefs(
    x86_dasm_t *d,              /* disassembler object */
    uint32_t target_offset,     /* absolute address of target byte */
    const dasm_xref_t *prev)    /* previous xref; NULL for first one */   
{
    const dasm_xref_t *first = VECTOR_DATA(d->entry_points);
    const dasm_xref_t *xref;

    /* If target is -1, return the next xref without filtering target. */
    if (target_offset == (uint32_t)(-1))
    {
        xref = (prev == NULL)? first : prev + 1;
        return (xref < first + VECTOR_SIZE(d->entry_points))? xref : NULL;
    }

    /* If prev is NULL, find the first xref that matches the target. */
    if (prev == NULL) 
    {
        dasm_xref_t match;
        match.target.seg = (uint16_t)(target_offset >> 4);
        match.target.off = (uint16_t)(target_offset & 0xf);
        
        xref = bsearch(&match, first, VECTOR_SIZE(d->entry_points), sizeof(match),
            compare_xrefs_by_target);
        if (xref == NULL)
            return NULL;

        /* If there are multiple matches, bsearch() may return any one of
         * them. So we need to move the pointer to the first one.
         */
        while (xref > first && FARPTR_TO_OFFSET(xref[-1].target) == target_offset)
            --xref;
        return xref;
    }

    /* Return the next xref if it matches target_offset. */
    xref = prev + 1;
    if (xref < first + VECTOR_SIZE(d->entry_points) &&
        FARPTR_TO_OFFSET(xref->target) == target_offset)
        return xref;
    else
        return NULL;
}
