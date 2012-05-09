#include <iostream>
#include <cstdint>
#include <cstring>
#include <utility>
#include "cpr/file_mapping.h"
#include "x86codec/x86_codec.h"

static void hex_dump(const void *_p, size_t size)
{
	static const char *output = "0123456789abcdef";
	const unsigned char *p = (const unsigned char *)_p;

	for (size_t i = 0; i < size; ++i)
	{
		if (i > 0 && i % 16 == 0)
			std::cout << std::endl;

		unsigned char c = p[i];
		std::cout << output[(c>>4)&0xf] << output[c&0xf] <<  ' ';
	}
	std::cout << std::endl;
}

/// Relocation entry in a DOS MZ executable (.EXE).
struct MZRelocEntry
{
	uint16_t off;
	uint16_t seg;
};

/// File header in a DOS MZ executable (.EXE).
struct MZHeader
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
};

/// File format reader for DOS MZ executable (.EXE).
class MZReader
{
	const char *_pmem; /* pointer to memory mapped file */
	size_t _size;      /* size in bytes of the used region of the .EXE file */
	MZHeader _header;  /* header in the .EXE file */
	size_t _start;     /* offset of the start of the executable image */

public:

	MZReader() : _pmem(NULL), _size(0)
	{
		memset(&_header, 0, sizeof(_header));
	}

	void unload()
	{
		_pmem = NULL;
		_size = 0;
		memset(&_header, 0, sizeof(_header));
	}

	bool load(const void *pmem, size_t size)
	{
#define REQUIRE(cond) \
	do { \
		if (!(cond)) { \
			unload(); \
			return false; \
		} \
	} while (0)

		// Initialize members.
		REQUIRE(size >= sizeof(_header));
		_pmem = (const char *)pmem;
		_size = size;
		memcpy(&_header, pmem, sizeof(_header));

		// Check signature. Both 'MZ' and 'ZM' are allowed.
		REQUIRE(_header.signature == 0x5A4D || _header.signature == 0x4D5A);

		// Compute the size of the executable, and update the _size member.
		REQUIRE(_header.page_count > 0);
		size_t used_size = (size_t)_header.page_count * 512 - 
			(_header.last_page_size ? 512 - _header.last_page_size : 0);
		REQUIRE(used_size <= _size);
		_size = used_size;

		// Load relocation table.

		// Check header size.
		_start = (size_t)_header.header_size * 16;
		REQUIRE(_start <= _size);

		return true;

#undef REQUIRE
	}

	const void *image_address() const
	{
		return _pmem + _start;
	}

	size_t image_size() const
	{
		return _size - _start;
	}
};

// Test x86 disassembler.
static void test_decode()
{
    unsigned char code[] = {
        0x03, 0x05, 0x00, 0x00, 0x00, 0x00 // ADD EAX, dword ptr [0]
    };
    
    x86_insn_t insn;
    x86_options_t opt;
    opt.mode = X86_MODE_32BIT;
    
    int count = x86_decode(code, &insn, &opt);
    if (count <= 0)
    {
        std::cerr << "Invalid instruction!" << std::endl;
        return;
    }
    if (count != sizeof(code))
    {
        std::cerr << "Decode wrong!" << std::endl;
        return;
    }
    std::cout << "Decode OK.\n";
}

int main(int argc, char* argv[])
{
#if 0
	if (argc <= 1)
	{
		std::cerr << "Expecting file name as first argument.\n";
		return 1;
	}
#endif

    test_decode();
    return 0;

	const char *filename = "data/H.EXE";

	// Map the file into memory.
	mmap_t *mm = mmap_open(filename, MMAP_READ|MMAP_READLOCK);
	if (!mm)
	{
		std::cerr << "Cannot load file '" << filename << "'." << std::endl;
		return 1;
	}

	// Parse the file.
	MZReader reader;
	if (!reader.load(mmap_address(mm), mmap_size(mm)))
	{
		std::cerr << "The file format is not supported." << std::endl;
		return 1;
	}

	std::cout << "Image size: " << reader.image_size() << std::endl;

	// Produce a hex-dump of the first few bytes of the image.
	hex_dump(reader.image_address(), std::min(reader.image_size(), (size_t)256));

	// Release resources.
	mmap_close(mm);

	return 0;
}
