/*

	MIT License

	Copyright (c) 2021 Kento Oki

	Permission is hereby granted, free of charge, to any person obtaining a copy
	of this software and associated documentation files (the "Software"), to deal
	in the Software without restriction, including without limitation the rights
	to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
	copies of the Software, and to permit persons to whom the Software is
	furnished to do so, subject to the following conditions:

	The above copyright notice and this permission notice shall be included in all
	copies or substantial portions of the Software.

	THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
	IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
	FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
	AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
	LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
	OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
	SOFTWARE.

*/

#pragma once
#include "main.hpp"

namespace kernel_image
{
	constexpr uint8_t jmp_shellcode[] = {
		0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,               // jmp qword ptr [rip + 0x0]
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }; // 0xADDRESS

	bool deploy(void* base_address, void* function, size_t* size, void** original_bytes);
	void restore(void* base_address, const void* original_bytes, const size_t size);

	template<size_t N>
	bool is_deployable(const void* destination)
	{
		uint8_t zero_bytes[N] = { 0 };
		memset(&zero_bytes, 0, N);
		return !memcmp(destination, &zero_bytes, N);
	}

	template<size_t N>
	void* find_codecave(void* image_base)
	{
		const auto nt_headers = RtlImageNtHeader(image_base);
		const auto* section = IMAGE_FIRST_SECTION(nt_headers);

		for (auto i = 0ul; i < nt_headers->FileHeader.NumberOfSections; i++, section++)
		{
			if (!strcmp(reinterpret_cast<const char*>(&section->Name), "INIT"))
				continue;

			if ((section->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			&& !(section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE))
			{
				const auto section_base =
					reinterpret_cast<u64>(image_base)
					+ section->VirtualAddress
					+ section->Misc.VirtualSize;

				for (auto x = section_base; x < section_base + section->SizeOfRawData; x++)
					if (is_deployable<N>(reinterpret_cast<void*>(x)))
						return reinterpret_cast<void*>(x);
			}
		}

		return nullptr;
	}
}