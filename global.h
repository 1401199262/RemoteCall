#pragma once

#include <ntifs.h>
#include <ntddk.h>
#include <ntimage.h>
#include <ntstrsafe.h>
#include <intrin.h>
#include <windef.h>

#define E(a) a
#define EPtr(a) a
#define ImpCall(a,...) (a(__VA_ARGS__))

#include "Define.h"


#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define ToUpper(Char) ((Char >= 'a' && Char <= 'z') ? (Char - 'a') : Char)
#define NT_HEADER(Base) (PIMAGE_NT_HEADERS)((ULONG64)(Base) + ((PIMAGE_DOS_HEADER)(Base))->e_lfanew)

template <typename StrType, typename StrType2>
__forceinline bool StrICmp(StrType Str, StrType2 InStr, bool CompareFull) {
	if (!Str || !InStr) return false;
	wchar_t c1, c2; do {
		c1 = *Str++; c2 = *InStr++;
		c1 = ToLower(c1); c2 = ToLower(c2);
		if (!c1 && (CompareFull ? !c2 : 1))
			return true;
	} while (c1 == c2);

	return false;
}

inl PVOID GetProcAddress(PVOID ModBase, const char* Name)
{
	if (!ModBase) return 0;
	//parse headers
	PIMAGE_NT_HEADERS NT_Head = NT_HEADER(ModBase);
	PIMAGE_EXPORT_DIRECTORY ExportDir = (PIMAGE_EXPORT_DIRECTORY)((ULONG64)ModBase + NT_Head->OptionalHeader.DataDirectory[0].VirtualAddress);

	//process records
	for (ULONG i = 0; i < ExportDir->NumberOfNames; i++)
	{
		//get ordinal & name
		USHORT Ordinal = ((USHORT*)((ULONG64)ModBase + ExportDir->AddressOfNameOrdinals))[i];
		const char* ExpName = (const char*)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfNames))[i];

		//check export name
		if (StrICmp(Name, ExpName, true))
			return (PVOID)((ULONG64)ModBase + ((ULONG*)((ULONG64)ModBase + ExportDir->AddressOfFunctions))[Ordinal]);
	}

	//no export
	return nullptr;
}



//eptred var
extern PVOID NtBase;
extern PDRIVER_OBJECT g_DriverObject;
extern "C" int _fltused;

#include "util.h"



//#define OPT_OFF #pragma optimize("", off)
//#define OPT_ON #pragma optimize("", on)


