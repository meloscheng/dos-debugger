#include <iostream>
#include <cstdint>
#include <cstring>
#include <utility>

#include "x86codec/x86_codec.h"
#include "mz.h"

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

#if 0
// Test x86 disassembler.
static void test_decode()
{
    unsigned char code[] = {
        0x03, 0x05, 0x00, 0x00, 0x00, 0x00 // ADD EAX, dword ptr [0]
    };
    
    x86_insn_t insn;
    x86_options_t opt;
    opt.mode = OPR_16BIT;
    
    int count = x86_decode(code, &code[6], &insn, &opt);
    if (count <= 0)
    {
        std::cerr << "Invalid instruction!" << std::endl;
        return;
    }
    
    // Display the string.
    char text[256];
    x86_format(&insn, text, X86_FMT_INTEL|X86_FMT_LOWER);
    std::cout << text << std::endl;
#if 0
    if (count != sizeof(code))
    {
        std::cerr << "Decode wrong!" << std::endl;
        return;
    }
#endif
    std::cout << "Finished." << std::endl;
}
#endif

int main(int argc, char* argv[])
{
#if 0
	if (argc <= 1)
	{
		std::cerr << "Expecting file name as first argument.\n";
		return 1;
	}
#endif

#if 0
    test_decode();
    return 0;
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
#if 0
    size_t start = 0x7430; // This is program entry
#elif 0
    size_t start = 0x0010; // first instruction
#elif 0
    //size_t start = 0x3770; // near a jump table
    size_t start = 0x37B4; // after jump table
#else
    size_t start = 0x17fc; // This is proc OutputDecodedPage
#endif
    size_t total = mz_image_size(file);
    x86_options_t opt;
    opt.mode = OPR_16BIT;
    const unsigned char *code = mz_image_address(file);
    const unsigned char *p = code + start;
    for ( ; p < code + total; )
    {
        x86_insn_t insn;
        int count = x86_decode(p, code + total, &insn, &opt);
        if (count <= 0)
        {
            std::cout << "Invalid instruction." << std::endl;
#if 0
            __debugbreak();
            continue;
#else
            break;
#endif
        }

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
    }

	// Produce a hex-dump of the first few bytes of the image.
	// hex_dump(reader.image_address(), std::min(reader.image_size(), (size_t)256));

	return 0;
}
