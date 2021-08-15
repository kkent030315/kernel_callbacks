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

inline PCALLBACK_ROUTINE_BLOCK(NTAPI* ExReferenceCallBackBlock)(PVOID);
inline VOID(NTAPI* ExDereferenceCallBackBlock)(PVOID, PVOID);
inline PVOID(NTAPI* ExGetCallBackBlockRoutine)(PVOID);

namespace pirate
{
	// 21H1 19043.1165 ntoskrnl.exe 10.0.19041.1165
	constexpr auto RvaPspCreateProcessNotifyRoutine      = 0xCEC2E0;
	constexpr auto RvaExReferenceCallBackBlock           = 0x24CB50;
	constexpr auto RvaExDereferenceCallBackBlock         = 0x24CC10;

	inline void** PspCreateProcessNotifyRoutine         = { 0 };
	inline uint32_t* PspCreateProcessNotifyRoutineCount = nullptr;

	inline bool initialized = false;

	void init();

	template<typename Fn>
	bool each_process_callback(Fn callback, void* context = nullptr)
	{
		bool res = false;

		if (!initialized)
			return false;

		KeEnterCriticalRegion();

		for (auto i = 0ul; i < PSP_MAX_CREATE_PROCESS_NOTIFY; i++)
		{
			const auto entry = &PspCreateProcessNotifyRoutine[i];
			
			if (const auto callback_block = ExReferenceCallBackBlock(entry))
			{
				res = callback(callback_block, context);
				ExDereferenceCallBackBlock(entry, callback_block);
				if (res) break;
			}
		}

		KeLeaveCriticalRegion();
		return res;
	}
}