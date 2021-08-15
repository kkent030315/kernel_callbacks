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

#include "main.hpp"

// This is just an example, this does not have mutex.
PROCESS_CALLBACK_DESCRIPTOR process_callback_registration[64] = { 0 };
uint32_t process_callback_count = 0;

void* ntos_image_base()
{
	void* image_base;
	RtlLookupFunctionEntry(reinterpret_cast<u64>(&x86BiosCall), reinterpret_cast<u64*>(&image_base), nullptr);
	return image_base;
}

bool write_to_readonly(void* dst, const void* src, const size_t size)
{
	bool ret = true;
	const PMDL mdl = IoAllocateMdl(dst, size, FALSE, FALSE, nullptr);

	if (!mdl)
		return false;

	__try
	{
		MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

		void* mapped_kva = MmMapLockedPagesSpecifyCache(mdl, KernelMode, MmNonCached, nullptr, FALSE, HighPagePriority);
		if (!mapped_kva)
		{
			ret = false;
			MmUnlockPages(mdl);
			goto exit;
		}

		memcpy(mapped_kva, src, size);

		MmUnmapLockedPages(mapped_kva, mdl);
		MmUnlockPages(mdl);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		ret = false;
	}

exit:
	IoFreeMdl(mdl);

	return true;
}

template<typename Fn>
bool each_module(const Fn callback, void* context = nullptr)
{
	bool ret = false;
	KeEnterCriticalRegion();

	if (ExAcquireResourceExclusiveLite(PsLoadedModuleResource, TRUE))
	{
		for (const auto* entry = PsLoadedModuleList;
			entry != PsLoadedModuleList->Blink;
			entry = entry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY ldr_entry =
				CONTAINING_RECORD(entry, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);

			if (ret = callback(ldr_entry, context))
				break;
		}

		ExReleaseResourceLite(PsLoadedModuleResource);
	}
	else
		ret = false;

	KeLeaveCriticalRegion();
	return ret;
}

bool deploy_process_callback(void* deployment, void* function)
{
	size_t shell_size;
	void* original_bytes;
	kernel_image::deploy(deployment, function, &shell_size, &original_bytes);

	if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE>(deployment), FALSE)))
	{
		process_callback_registration[process_callback_count] = { shell_size, deployment, original_bytes };
		InterlockedIncrement(reinterpret_cast<volatile LONG*>(&process_callback_count));
		return true;
	}
	else
		kernel_image::restore(deployment, original_bytes, shell_size);

	return false;
}

template<typename Fn>
bool register_process_callback(PG_BYPASS_MODE mode, Fn notify_routine)
{
	switch (mode)
	{
	case CodeCave:
		return each_module([&](const PLDR_DATA_TABLE_ENTRY ldr_entry, void*) -> bool
			{
				if (const auto code_cave =
					kernel_image::find_codecave<sizeof(kernel_image::jmp_shellcode)>(ldr_entry->DllBase))
				{
					printk("codecave found at 0x%p(%wZ+0x%llX)\n", code_cave, &ldr_entry->BaseDllName, reinterpret_cast<u64>(code_cave) - reinterpret_cast<u64>(ldr_entry->DllBase));
					return deploy_process_callback(code_cave, +notify_routine);
				}

				return false;
			});

	case Hijack:
		pirate::init();
		return pirate::each_process_callback([&](const CALLBACK_ROUTINE_BLOCK* block, void*)
			{
				if (each_module([&](const PLDR_DATA_TABLE_ENTRY ldr_entry, void*)
					{
						const auto start = ldr_entry->DllBase;
						const auto end = reinterpret_cast<void*>(reinterpret_cast<u64>(ldr_entry->DllBase) + ldr_entry->SizeOfImage);

						const auto address_within_range = block->Function >= start && block->Function <= end;
						const auto not_ntoskrnl = !!wcscmp(L"ntoskrnl.exe", ldr_entry->BaseDllName.Buffer);

						if (address_within_range && not_ntoskrnl)
							printk("hijacking %wZ process callback [0x%p]...\n", &ldr_entry->BaseDllName, block->Function);

						return address_within_range && not_ntoskrnl;
					}))
				{
					if (deploy_process_callback(block->Function, +notify_routine))
					{
						printk("0x%p is now hijacked\n", block->Function);
						return true;
					}

					return false;
				}

				return false;
			});
	default:
		return false;
	}
}

void driver_unload(PDRIVER_OBJECT driver_object)
{
	for (auto i = 0; i < process_callback_count; i++)
	{
		const auto entry = &process_callback_registration[i];
		if (NT_SUCCESS(PsSetCreateProcessNotifyRoutine(reinterpret_cast<PCREATE_PROCESS_NOTIFY_ROUTINE>(entry->function), TRUE)))
			kernel_image::restore(entry->function, entry->original_bytes, entry->size_of_shellcode);
	}
}

ntstatus DriverEntry(PDRIVER_OBJECT driver_object, PUNICODE_STRING registry_path)
{
	if (driver_object)
		driver_object->DriverUnload = driver_unload;

	printk("driver entry\n");

	register_process_callback(CodeCave, []() { printk("trampoline process callback called\n"); });
	register_process_callback(Hijack,   []() { printk("hijacked process callback called\n"); });

	return STATUS_SUCCESS;
}