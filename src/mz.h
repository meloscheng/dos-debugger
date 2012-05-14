/* mz.h -- routines for loading DOS MZ executable (.EXE) */

#ifndef MZ_H
#define MZ_H

#include <stdint.h>
#include "x86_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Represents a 16-bit far pointer. */
typedef x86_farptr16_t mz_farptr_t;

/* File header in a DOS MZ executable. */
typedef struct mz_header_t
{
	uint16_t signature;        /* 00: file format signature, should be 0x5A4D ('MZ') */
	uint16_t last_page_size;   /* 02: size of last page in bytes; 0 means full */
	uint16_t page_count;       /* 04: number of 512-byte pages in the file, 
							          including the last page */
	uint16_t reloc_count;      /* 06: number of relocation entries; may be 0 */
	uint16_t header_size;      /* 08: size of header in 16-byte paragraphs /
	                                  this is also where the executable image starts */
	uint16_t min_alloc;        /* 0A: minimum memory required, in paragraphs */
	uint16_t max_alloc;        /* 0C: maximum memory required, in paragraphs;
							          usually 0xFFFF */
	uint16_t reg_ss;           /* 0E: initial value of SS; must be relocated */
	uint16_t reg_sp;           /* 10: initial value of SP */
	uint16_t checksum;         /* 12: checksum of the .EXE file; usually not used */
	uint16_t reg_ip;           /* 14: initial value of IP */
	uint16_t reg_cs;           /* 16: initial value of CS; must be relocated */
	uint16_t reloc_off;        /* 18: offset (in bytes) of relocation table */
	uint16_t overlay;          /* 1A: overlay number; usually 0 */
} mz_header_t;

struct mz_file_t;
typedef struct mz_file_t mz_file_t;

/* Opens a DOS MZ executable file. */
mz_file_t *mz_open(const char *filename);

/* Closes a DOS MZ executable file. */
void mz_close(mz_file_t *file);

/* Gets a pointer to the executable image. */
unsigned char *mz_image_address(mz_file_t *file);

/* Gets the size, in bytes, of the executable image. */
size_t mz_image_size(const mz_file_t *file);

/* Gets the number of relocation entries. */
size_t mz_reloc_count(const mz_file_t *file);

/* Gets the content of a relocation entry. Returns a far pointer, relative to
 * the start of the executable image, that points to a 16-bit word which
 * contains a segment address. The module loader should add the loaded segment
 * to the word at this location.
 */
mz_farptr_t mz_reloc_entry(const mz_file_t *file, size_t i);

/* Returns the address of the first instruction to execute. The address is
 * relative to the start of the executable image.
 */
mz_farptr_t mz_program_entry(const mz_file_t *file);

#ifdef __cplusplus
}
#endif

#endif /* MZ_H */
