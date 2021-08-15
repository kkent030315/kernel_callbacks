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
#include <windef.h>

#define PSP_MAX_CREATE_PROCESS_NOTIFY 64

typedef struct _LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

typedef struct _CALLBACK_ROUTINE_BLOCK
{
	EX_RUNDOWN_REF RundownProtect;
	PEX_CALLBACK_FUNCTION Function;
	PVOID Context;
} CALLBACK_ROUTINE_BLOCK, * PCALLBACK_ROUTINE_BLOCK;

EXTERN_C NTSYSAPI PLIST_ENTRY PsLoadedModuleList;
EXTERN_C NTSYSAPI PERESOURCE PsLoadedModuleResource;

EXTERN_C
NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(IN PVOID ModuleAddress);

EXTERN_C
NTSYSAPI
PVOID
NTAPI
RtlLookupFunctionEntry(
	IN ULONGLONG ControlPc,
	OUT PULONGLONG ImageBase,
	OUT PULONGLONG TargetGp);

EXTERN_C
NTSYSAPI
BOOLEAN
x86BiosCall(
	ULONG InterruptNumber,
	PVOID Registers);