#pragma once
#include "ketamine.h"

extern "C" PEB* GetProcessEnvironment();

extern "C" void __security_check_cookie() { };
extern "C" void _DllMainCRTStartup() { };

namespace Memory
{

	inline unsigned __int64 GetModuleBase(const wchar_t* Name)
	{
		const PEB* Peb = GetProcessEnvironment();

		if (!Peb)
			return 0;

		const LIST_ENTRY ModuleList = Peb->Ldr->ModuleListMemoryOrder;

		for (LIST_ENTRY Current = ModuleList; Current.Flink != &Peb->Ldr->ModuleListMemoryOrder; Current = *Current.Flink)
		{
			LDR_DATA_TABLE_ENTRY* pModule = reinterpret_cast<LDR_DATA_TABLE_ENTRY*>(CONTAINING_RECORD(Current.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderModuleList));

			if (pModule->BaseDllName.Buffer)
			{
				if (strcmp(pModule->BaseDllName.Buffer, Name))
				{
					return (unsigned __int64)pModule->DllBase;
				}
			}
		}

		return 0;
	}

	inline void* GetModuleExport(unsigned __int64 Module, const char* Name)
	{
		const IMAGE_DOS_HEADER* DosHeader = reinterpret_cast<const IMAGE_DOS_HEADER*>(Module);
		const IMAGE_NT_HEADERS* NTHeader = reinterpret_cast<const IMAGE_NT_HEADERS*>(Module + DosHeader->e_lfanew);

		const IMAGE_DATA_DIRECTORY* DataDirectory = reinterpret_cast<const IMAGE_DATA_DIRECTORY*>(&NTHeader->OptionalHeader.DataDirectory[0]);
		const IMAGE_EXPORT_DIRECTORY* ExportDirectory = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(Module + DataDirectory->VirtualAddress);

		const unsigned long* NameTable = reinterpret_cast<const unsigned long*>(Module + ExportDirectory->AddressOfNames);
		const unsigned long* RVATable = reinterpret_cast<const unsigned long*>(Module + ExportDirectory->AddressOfFunctions);
		const unsigned short* OrdTable = reinterpret_cast<const unsigned short*>(Module + ExportDirectory->AddressOfNameOrdinals);

		if (ExportDirectory)
		{
			for (int i = 0; i < ExportDirectory->NumberOfNames; i++)
			{
				const char* ExportName = reinterpret_cast<const char*>(Module + NameTable[i]);

				if (strcmp(ExportName, Name))
				{
					return reinterpret_cast<void*>(Module + RVATable[OrdTable[i]]);
				}
			}
		}

		return 0;
	}

}