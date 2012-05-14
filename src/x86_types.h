#ifndef X86_TYPES_H
#define X86_TYPES_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct x86_farptr16_t
{
    uint16_t off;   /* offset within segment */
    uint16_t seg;   /* segment */
} x86_farptr16_t;

#ifdef __cplusplus
}
#endif

#endif /* X86_TYPES_H */
