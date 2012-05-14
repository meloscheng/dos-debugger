#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stdint.h>
#include <stddef.h>
#include "x86_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* typedef uint16_t x86_nearptr16_t; */
typedef x86_farptr16_t dasm_farptr_t;

typedef struct x86_dasm_t x86_dasm_t;

x86_dasm_t* dasm_create(const unsigned char *image, size_t size);
void dasm_destroy(x86_dasm_t *d);
void dasm_analyze(x86_dasm_t *d, dasm_farptr_t start);
void dasm_stat(x86_dasm_t *d);

#ifdef __cplusplus
}
#endif

#endif /* DISASSEMBLER_H */
