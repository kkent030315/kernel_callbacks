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

#include "kernel_image.hpp"

bool kernel_image::deploy(void* base_address, void* function, size_t* size, void** original_bytes)
{
	uint8_t shellcode[sizeof(jmp_shellcode)];
	memcpy(&shellcode, &jmp_shellcode, sizeof(shellcode));
	*reinterpret_cast<void**>(shellcode + 0x6) = function;
	if (size) *size = sizeof(jmp_shellcode);
	if (original_bytes)
		if (void* buffer = ExAllocatePool(NonPagedPoolNx, sizeof(jmp_shellcode)))
		{
			memcpy(buffer, base_address, sizeof(jmp_shellcode));
			*original_bytes = buffer;
		}
	return write_to_readonly(base_address, &shellcode, sizeof(shellcode));
}

void kernel_image::restore(void* base_address, const void* original_bytes, const size_t size)
{
	write_to_readonly(base_address, original_bytes, size);
	ExFreePool(const_cast<void*>(original_bytes));
}