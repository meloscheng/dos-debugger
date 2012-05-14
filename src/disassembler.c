#include "disassembler.h"
#include "x86codec/x86_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define MAX2(a,b) ((a) > (b) ? (a) : (b))

#define FARPTR_TO_OFFSET(p) (((uint32_t)(p).seg << 4) | (uint32_t)(p).off)

#define VECTOR_STRUCT(Ty)   \
    struct {                \
        size_t elemsize;    \
        Ty *p;              \
        size_t count;       \
        size_t capacity;    \
    }

typedef VECTOR_STRUCT(void) VECTOR_VOID_STRUCT;

#define VECTOR(Ty) VECTOR_STRUCT(Ty) *

#define VECTOR_CREATE(v, Ty) \
    do { \
        (v) = calloc(1, sizeof(VECTOR_VOID_STRUCT)); \
        (v)->elemsize = sizeof(Ty); \
    } while (0)

#define VECTOR_DESTROY(v) \
    do { \
        if (v) { \
            free((v)->p); \
            free(v); \
        } \
    } while (0)

/* Returns a reference to the i-th element in the vector. */
#define VECTOR_AT(v, i) ((v)->p[i])

/* Returns a boolean value indicating whether the vector is empty. */
#define VECTOR_EMPTY(v) ((v)->count == 0)

/* Returns the number of elements in a vector. */
#define VECTOR_SIZE(v) ((v)->count)

/* Reserves at least _cap_ elements in the vector, and returns a pointer
 * to the (possibly reallocated) underlying buffer.
 */
#define VECTOR_RESERVE(v,cap) \
    ( \
        ((cap) <= (v)->capacity) ? \
            ((v)->p) : \
            ((v)->p = realloc((v)->p, (v)->elemsize * ((v)->capacity = cap))) \
    )

/* Push an element to the end of the array. Returns an lvalue that refers to
 * the pushed element.
 */
#define VECTOR_PUSH(v,elem) \
    ( \
        ( ((v)->count < (v)->capacity)? (v)->p : \
              VECTOR_RESERVE(v, MAX2(10, (v)->capacity * 2)) \
        ) [++(v)->count - 1] = (elem) \
    )

/* Pop an element from the end of the vector. Returns an lvalue to the element
 * originally stored at the end of the vector.
 */
#define VECTOR_POP(v) ((v)->p[--(v)->count])

#if 1
#define QUEUE(Ty) VECTOR(Ty)
//#define QUEUE_INIT(Ty) VECTOR_INIT(Ty)
#define QUEUE_CREATE(q,Ty) VECTOR_CREATE(q,Ty)
#define QUEUE_DESTROY(q) VECTOR_DESTROY(q)
#define QUEUE_EMPTY(q) VECTOR_EMPTY(q)
#define QUEUE_PUSH(q,elem) VECTOR_PUSH(q,elem)
#define QUEUE_POP(q) VECTOR_POP(q)
#endif

typedef unsigned char byte_attr_t;

#define ATTR_TYPE       3
#define TYPE_UNKNOWN    0   /* the byte is not processed and its attribute is indeterminate */
#define TYPE_PENDING    1   /* the byte is scheduled for analysis */
#define TYPE_CODE       2   /* the byte is part of an instruction */
#define TYPE_DATA       3   /* the byte is part of a data item */

#define ATTR_PROCESSED  2   /* indicates that the byte is processed */

#define ATTR_BOUNDARY   4   /* indicates that the byte is the first byte of
                             * an instruction or data item.
                             */

enum dasm_entry_type
{
    ENTRY_USER_SPECIFIED        = 0,    /* user specified entry point (e.g. program start) */
    ENTRY_FUNCTION_CALL         = 1,    /* a CALL instruction refers to this location */
    ENTRY_CONDITIONAL_JUMP      = 2,    /* a Jcc instruction refers to this location */
    ENTRY_UNCONDITIONAL_JUMP    = 3,    /* a JUMP instruction refers to this location */
    ENTRY_INDIRECT_JUMP         = 4,    /* a JUMP instruction where the jump target address
                                         * is given in a memory location (such as jump
                                         * table).
                                         */
    ENTRY_RETURN_FROM_CALL      = 5,    
    ENTRY_RETURN_FROM_INTERRUPT = 6,    
#if 0
    ENTRY_NEAR_JUMP_TABLE       = 7,    /* the word at this location appears to represent
                                         * a relative offset to a JUMP NEAR instruction.
                                         * The instruction is stored in _from_.
                                         */
    ENTRY_FAR_JUMP_TABLE        = 8,    /* the dword at this location appears to represent
                                         * an absolute address (seg:ptr) of a JUMP FAR
                                         * instruction.
                                         */
#endif
};

static const char *get_entry_type_string(enum dasm_entry_type type)
{
#define CASE(x) case x : return #x 
    switch (type)
    {
        CASE(ENTRY_USER_SPECIFIED);
        CASE(ENTRY_FUNCTION_CALL);
        CASE(ENTRY_CONDITIONAL_JUMP);
        CASE(ENTRY_UNCONDITIONAL_JUMP);
        CASE(ENTRY_INDIRECT_JUMP);
        CASE(ENTRY_RETURN_FROM_CALL);
        CASE(ENTRY_RETURN_FROM_INTERRUPT);
    default:
        return "ENTRY_UNKNOWN";
    }
#undef CASE
}

typedef uint32_t dasm_off_t;

typedef struct dasm_entry_t
{
    x86_farptr16_t start;           /* address of the entry point */
    enum dasm_entry_type reason;    /* why is this byte an entry point */
    x86_farptr16_t from;            /* where is it from */
} dasm_entry_t;

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
    VECTOR(dasm_entry_t) entry_points; /* dasm_code_block_t code_blocks */
    /* however, it is not exactly a block; it is more like an entry point */
    VECTOR(dasm_jump_table_t) jump_tables;
} x86_dasm_t;

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

    VECTOR_CREATE(d->entry_points, dasm_entry_t);
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
            dasm_entry_t target;
            target.start.seg = start.seg;
            target.start.off = start.off + count + insn->oprs[0].val.rel;
            target.reason = ENTRY_UNCONDITIONAL_JUMP;
            target.from = start;
            VECTOR_PUSH(d->entry_points, target);
            return FLOW_FINISH_BLOCK;
        }
        if (insn->oprs[0].type == OPR_PTR) /* far jump to absolute address */
        {
            dasm_entry_t target;
            target.start.seg = insn->oprs[0].val.ptr.seg;
            target.start.off = (uint16_t)insn->oprs[0].val.ptr.off;
            target.reason = ENTRY_UNCONDITIONAL_JUMP;
            target.from = start;
            VECTOR_PUSH(d->entry_points, target);
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
    if (op == I_CALL && insn->oprs[0].type == OPR_REL)
    {
        dasm_entry_t target;
        target.start.seg = start.seg;
        target.start.off = start.off + count + insn->oprs[0].val.rel;
        target.reason = ENTRY_FUNCTION_CALL;
        target.from = start;
        VECTOR_PUSH(d->entry_points, target);
        return FLOW_CONTINUE;
    }
    if (op == I_CALLF && insn->oprs[0].type == OPR_PTR)
    {
        dasm_entry_t target;
        target.start.seg = insn->oprs[0].val.ptr.seg;
        target.start.off = (uint16_t)insn->oprs[0].val.ptr.off;
        target.reason = ENTRY_FUNCTION_CALL;
        target.from = start;
        VECTOR_PUSH(d->entry_points, target);
        return FLOW_CONTINUE;
    }
        
    /* If this is a Jcc instruction, push the jump target to the queue, and
     * follow the flow assuming no jump.
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
    case I_JLE:
    case I_JNLE:
        if (insn->oprs[0].type == OPR_REL) /* jump to relative position */
        {
            dasm_entry_t target;
            target.start.seg = start.seg;
            target.start.off = start.off + count + insn->oprs[0].val.rel;
            target.reason = ENTRY_CONDITIONAL_JUMP;
            target.from = start;
            VECTOR_PUSH(d->entry_points, target);
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
    size_t total = d->image_size, code = 0, data = 0;

    for (b = 0; b < total; b++)
    {
        if ((d->attr[b] & ATTR_TYPE) == TYPE_CODE)
            ++code;
        else if ((d->attr[b] & ATTR_TYPE) == TYPE_DATA)
            ++data;
    }

    fprintf(stderr, "Total: %d bytes\n", total);
    fprintf(stderr, "Code: %d bytes\n", code);
    fprintf(stderr, "Data: %d bytes\n", data);

    fprintf(stderr, "Jump tables: %d\n", VECTOR_SIZE(d->jump_tables));
}

static int verbose = 1;

/* Analyze the code block starting at location _start_ recursively. 
 * Return one of the following status codes:
 *
 * FLOW_CONTINUE
 *     The block was successfully analyzed.
 * FLOW_FINISH_BLOCK
 *     The block was already analyzed and nothing was done.
 */
void analyze_code_block(x86_dasm_t *d, dasm_entry_t entry)
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
        dasm_farptr_t pos = VECTOR_AT(d->entry_points, i).start;
        dasm_farptr_t from = VECTOR_AT(d->entry_points, i).from;

        if (verbose)
        {
            printf("%04X:%04X  ; -- %s FROM %04X:%04X --\n", 
                pos.seg, pos.off, 
                get_entry_type_string(VECTOR_AT(d->entry_points, i).reason),
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
                fprintf(stderr, "%04X:%04X  %s\n", pos.seg, pos.off, text);
                fprintf(stderr, "           %s\n",
                    "JUMP target address cannot be determined by static analysis.");
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

void dasm_analyze(x86_dasm_t *d, dasm_farptr_t start)
{
    dasm_entry_t entry;
    size_t i = VECTOR_SIZE(d->jump_tables);

    /* Create an entry point using the user-supplied starting offset. */
    entry.start = start;
    entry.reason = ENTRY_USER_SPECIFIED;
    entry.from.seg = -1;
    entry.from.off = -1;

    /* Analyze the code block specified by the user. */
    analyze_code_block(d, entry);

    fprintf(stderr, "\n-- Statistics after initial analysis --\n");
    dasm_stat(d);
    //fprintf(stderr, "Initial analysis leaves us with %d jump tables.\n",
    //    VECTOR_SIZE(d->jump_tables) - i);

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

            entry.start.seg = insn_pos.seg;
            entry.start.off = target;
            entry.reason = ENTRY_INDIRECT_JUMP;
            entry.from = insn_pos;

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
