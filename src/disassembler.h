#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stddef.h>
#include "x86_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* typedef uint16_t x86_nearptr16_t; */

/* Typedef of a 16-bit far pointer used by the disassembler. */
typedef x86_farptr16_t dasm_farptr_t;

/* An opaque structure that represents a disassembler object. */
typedef struct x86_dasm_t x86_dasm_t;

/* Creates a disassembler for the given executable image. */
x86_dasm_t* dasm_create(const unsigned char *image, size_t size);

/* Destroys a disassembler previously created with dasm_create(). */
void dasm_destroy(x86_dasm_t *d);

/* Analyzes the code, starting at a given entry point. The code is analyzed
 * as much as possible by recursive traversal.
 */
void dasm_analyze(x86_dasm_t *d, dasm_farptr_t start);

/* Prints diagnostics information about a disassembler on standard error. */
void dasm_stat(x86_dasm_t *d);


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

#define ATTR_BLOCKSTART 8   /* indicates that this byte is the first byte of 
                             * an instruction that starts a basic block.
                             */

/* Returns the attribute of a given byte. */
byte_attr_t dasm_get_byte_attr(x86_dasm_t *d, uint32_t offset);

/* Enumerated values of xref types. */
typedef enum dasm_xref_type
{
    XREF_USER_SPECIFIED     = 0,    /* user specified entry point (e.g. program start) */
    XREF_FUNCTION_CALL      = 1,    /* a CALL instruction refers to this location */
    XREF_CONDITIONAL_JUMP   = 2,    /* a Jcc instruction refers to this location */
    XREF_UNCONDITIONAL_JUMP = 3,    /* a JUMP instruction refers to this location */
    XREF_INDIRECT_JUMP      = 4,    /* a JUMP instruction where the jump target address
                                     * is given in a memory location (such as jump
                                     * table).
                                     */
#if 0
    XREF_RETURN_FROM_CALL      = 5,    
    XREF_RETURN_FROM_INTERRUPT = 6,    
#endif

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
} dasm_xref_type;

/* Represents a cross-referential link in the code and data. For a xref 
 * between code and code, it is equivalent to an edge in a Control Flow Graph.
 */
typedef struct dasm_xref_t
{
    dasm_farptr_t target;   /* Target address being referenced. */
    dasm_farptr_t source;   /* Source address that refers to target. */
    dasm_xref_type type;    /* XRef type (e.g. function call, jump, etc). */
} dasm_xref_t;

/* Returns a user-friendly string that represents a xref type. */
const char * dasm_xref_type_string(enum dasm_xref_type type);

/* Enumerates the next link that refers to a given target address. To find the
 * first link that points to the address, supply NULL for _prev_. Then supply
 * the returned pointer for successive calls to this function, until the 
 * function returns NULL.
 *
 * If target_offset is set to -1, it enumerates all xrefs regardless of the
 * target.
 *
 * The supplied target address must be at an instruction boundary, i.e. it 
 * must points to the first byte of an instruction. If it points to the middle
 * of an instruction, or doesn't point to an instruction at all, no xref will
 * be returned.
 *
 * The target address is supplied as an absolute address instead of as a far
 * pointer because different far pointers (seg:off) may refer to the same
 * absolute address under the 8086 addressing method.
 */
const dasm_xref_t * dasm_enum_xrefs(
    x86_dasm_t *d,          /* disassembler object */
    uint32_t target_offset, /* absolute address of target byte */
    const dasm_xref_t *prev /* previous xref; NULL for first one */
    );

#ifdef __cplusplus
}
#endif

#endif /* DISASSEMBLER_H */
