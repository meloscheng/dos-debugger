#ifndef DISASSEMBLER_H
#define DISASSEMBLER_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct x86_dasm_t x86_dasm_t;

x86_dasm_t* dasm_create(const unsigned char *image, size_t size);
void dasm_destroy(x86_dasm_t *d);
void dasm_analyze(x86_dasm_t *d, size_t start);

#ifdef __cplusplus
}
#endif

#endif /* DISASSEMBLER_H */
