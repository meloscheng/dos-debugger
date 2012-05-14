#include <iostream>
#include <cstdint>
#include <cstring>
#include <utility>

#include "x86codec/x86_codec.h"
#include "mz.h"
#include "disassembler.h"

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

static void test_decode(const unsigned char *image, size_t size, size_t start)
{
    const unsigned char *p = image + start;
    x86_options_t opt;
    opt.mode = OPR_16BIT;
    
    for ( ; p < image + size; )
    {
        x86_insn_t insn;
        int count = x86_decode(p, image + size, &insn, &opt);
        if (count <= 0)
        {
            fprintf(stderr, "%s\n", "Invalid instruction.");
#if 0
            __debugbreak();
            continue;
#else
            break;
#endif
        }

        /* Output address. */
        printf("0000:%04X  ", (unsigned int)(p - image));

        /* Output binary code. */
        for (int i = 0; i < 8; i++)
        {
            if (i < count)
                printf("%02x ", p[i]);
            else
                printf("   ");
        }

        char text[256];
        x86_format(&insn, text, X86_FMT_INTEL|X86_FMT_LOWER);
        std::cout << text << std::endl;
        if (text[0] == '*')
            __debugbreak();
        else
            p += count;
    }
}

static void test_dasm(const unsigned char *image, size_t size, size_t offset)
{
    x86_dasm_t *d;
    dasm_farptr_t start;
    start.seg = 0;
    start.off = offset;

    d = dasm_create(image, size);
    dasm_analyze(d, start);
    dasm_stat(d);
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

	const char *filename = "data/H.EXE";

    /* Open the .EXE file. */
    mz_file_t *file = mz_open(filename);
    if (!file)
    {
		std::cerr << "The file format is not supported." << std::endl;
		return 1;
	}
	// std::cout << "Image size: " << reader.image_size() << std::endl;

    // Decode from a specific address.
#if 1
    size_t start = 0x7430; // This is program entry
#elif 0
    size_t start = 0x0010; // first instruction
#elif 0
    //size_t start = 0x3770; // near a jump table
    size_t start = 0x37B4; // after jump table
#else
    size_t start = 0x17fc; // This is proc OutputDecodedPage
#endif

#if 0
    // Decode instructions in serial from the starting position.
    test_decode(mz_image_address(file), mz_image_size(file), start);
#else
    // Disassemble the executable from a starting address.
    test_dasm(mz_image_address(file), mz_image_size(file), start);
    //test_dasm(mz_image_address(file), mz_image_size(file), 0x751C);
#endif

	// Produce a hex-dump of the first few bytes of the image.
	// hex_dump(reader.image_address(), std::min(reader.image_size(), (size_t)256));

	return 0;
}
