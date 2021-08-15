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
#include <ntddk.h>
#include <ntimage.h>
#include <cstdint>
#include "ntdefs.hpp"
#include "kernel_image.hpp"
#include "pirate.hpp"

#define printk DbgPrint

typedef NTSTATUS ntstatus;
typedef uint64_t u64;
typedef uint32_t u32;
typedef uint16_t u16;
typedef uint8_t u8;

typedef struct _PROCESS_CALLBACK_DESCRIPTOR
{
	size_t size_of_shellcode;
	void* function;
	void* original_bytes;
} PROCESS_CALLBACK_DESCRIPTOR, * PPROCESS_CALLBACK_DESCRIPTOR;

typedef enum _PG_BYPASS_MODE
{
	CodeCave = 0,
	Hijack
} PG_BYPASS_MODE;

#ifndef _WIN64
#error "Only x64 supported"
#endif // #ifndef _WIN64

bool write_to_readonly(void* dst, const void* src, const size_t size);
void* ntos_image_base();

DRIVER_UNLOAD driver_unload;
EXTERN_C DRIVER_INITIALIZE DriverEntry;

#ifdef ALLOC_PRAGMA
#pragma alloc_text("INIT", DriverEntry)
#endif // ALLOC_PRAGMA
