#include "disassembler.h"
#include "x86codec/x86_codec.h"
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>

#define MAX2(a,b) ((a) > (b) ? (a) : (b))

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

/* Returns a boolean value indicating whether the vector is empty. */
#define VECTOR_EMPTY(v) ((v)->count == 0)

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

static byte_attr_t attr[0x1000000]; /* 1MB bytes */

/* Represents an X86 disassembler. */
typedef struct x86_dasm_t
{
    const unsigned char *image;
    size_t image_size;
} x86_dasm_t;

x86_dasm_t * dasm_create(const unsigned char *image, size_t size)
{
    x86_dasm_t *d;
    d = (x86_dasm_t *)malloc(sizeof(x86_dasm_t));
    if (d == NULL)
        return NULL;
    d->image = image;
    d->image_size = size;
    return d;
}

void dasm_destroy(x86_dasm_t *d)
{
    free(d);
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
int decode_instruction(x86_dasm_t *d, size_t start, x86_insn_t *insn)
{
    size_t b = start;
    int count, i;
    x86_options_t opt = { OPR_16BIT };

    /* If the byte to analyze is already interpreted as data, return a 
     * conflict status.
     */
    if ((attr[b] & ATTR_TYPE) == TYPE_DATA)
        return ST_UNEXPECTED_DATA;

    /* If this byte to analyze is already interpreted as code, check that
     * it was treated as the first byte of an instruction. Otherwise, return
     * a conflict status.
     */
    if ((attr[b] & ATTR_TYPE) == TYPE_CODE)
    {
        if (attr[b] & ATTR_BOUNDARY)
            return ST_ALREADY_ANALYZED;
        else
            return ST_UNEXPECTED_CODE;
    }

    /* Decode an instruction at this location. */
    count = x86_decode(d->image + start, d->image + d->image_size, insn, &opt);
    if (count <= 0)
        return ST_BAD_INSTRUCTION;

    /* Check that the entire instruction covers unprocessed area. If any byte
     * in the area is already processed, return an error.
     */
    for (i = 1; i < count; i++)
    {
        if (attr[b + i] & ATTR_PROCESSED)
        {
            return (attr[b + i] & ATTR_TYPE) == TYPE_CODE ?
                ST_UNEXPECTED_CODE : ST_UNEXPECTED_DATA;
        }
    }

    /* Mark the bytes covered by the instruction as code. */
    for (i = 0; i < count; i++)
    {
        attr[b + i] &= ~ATTR_TYPE;
        attr[b + i] |= TYPE_CODE;
    }
            
    /* Return the number of bytes consumed. */
    return count;
}

#define FLOW_CONTINUE       0
#define FLOW_FINISH_BLOCK   1   

/* Analyze an instruction decoded from offset _start_ for _count_ bytes.
 */
int analyze_flow_instruction(x86_dasm_t *d, size_t start, size_t count, x86_insn_t *insn)
{
    int op = insn->op;

    /* If this is an unconditional JMP instruction, push the jump target to
     * the queue and finish this block.
     */
    if (op == I_JMP)
    {
        /* printf("About to JMP: \n"); */
        /* push to queue */
        return FLOW_FINISH_BLOCK;
    }

    /* If this is a CALL instruction, push the call target to the queue and
     * finish this block.
     *
     * Note: We need to know whether the subroutine being called will ever
     * return. For the moment we assume that it will return. 
     */
    if (op == I_CALL)
    {
        printf("About to CALL: \n");
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
    case I_JNBE:
        /* push to queue */
        return FLOW_CONTINUE;
    }

    /* This is not a flow-control instruction, so continue as usual. */
    return FLOW_CONTINUE;
}

void dasm_analyze(x86_dasm_t *d, size_t start)
{
    /* Create a list of pending code entry points to analyze. At the 
     * beginning, there is only one entry point, which is _start_.
     * As we encounter branch instructions (JMP, CALL, or Jcc) on the way, 
     * we push the target addresses to the queue of entry points, so 
     * that they can be analyzed later.
     */
    QUEUE(size_t) entry_points;
    QUEUE_CREATE(entry_points, size_t);
    QUEUE_PUSH(entry_points, start);

    /* Initialize all bytes in the image to unknown status. */
    memset(attr, 0, d->image_size);

    /* Decode the instruction at p. */
    while (!QUEUE_EMPTY(entry_points))
    {
        size_t pos = QUEUE_POP(entry_points);

        /* Keep decoding instructions starting from this location until
         * we encounter end-of-input, analyzed code/data, or any of the
         * jump instructions: RET/IRET/JMP/HLT/CALL
         */
        while (1)
        {
            x86_insn_t insn;
            int ret, count;
            
            /* Decode an instruction at this location. */
            ret = decode_instruction(d, pos, &insn);
            if (ret == ST_ALREADY_ANALYZED)
            {
                continue;
            }
            if (ret == ST_UNEXPECTED_DATA)
            {
                printf("Jump into data!\n");
                break;
            }
            if (ret == ST_UNEXPECTED_CODE)
            {
                printf("Jump into the middle of code!\n");
                break;
            }
            if (ret == ST_BAD_INSTRUCTION)
            {
                printf("Bad instruction!\n");
                break;
            }

            /* Analyse any flow-control instruction. */
            count = ret;
            ret = analyze_flow_instruction(d, start, count, &insn);
            if (ret == FLOW_FINISH_BLOCK)
                break;

            /* Advance the byte pointer. */
            pos += count;
        }
    }

    /* Release data. */
    QUEUE_DESTROY(entry_points);

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
