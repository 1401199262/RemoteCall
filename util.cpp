#include "global.h"
#include "PhysicalMemory.h"
#include "DispatchFunctions.h"
#include "util.h"

volatile u64 LastAllocation = 0;
volatile u64 LastAllocationAddress = 0;

NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize)
{
	if (!moduleStart)
		return STATUS_INVALID_PARAMETER;

	const auto listHeader = NQSI(SystemModuleInformation);
	if (!listHeader)
		return STATUS_MEMORY_NOT_ALLOCATED;

	auto currentModule = reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Module;
	for (size_t i = 0; i < reinterpret_cast<PSYSTEM_MODULE_INFORMATION>(listHeader)->Count; ++i, ++currentModule)
	{
		// \SystemRoot\system32\ntoskrnl.exe -> ntoskrnl.exe 
		const auto currentModuleName = reinterpret_cast<const char*>(currentModule->FullPathName + currentModule->OffsetToFileName);
		if (!strcmp(moduleName, currentModuleName))
		{
			*moduleStart = currentModule->ImageBase;
			if (moduleSize)
				*moduleSize = currentModule->ImageSize;
			KFree(listHeader);
			return STATUS_SUCCESS;
		}
	}
	KFree(listHeader);
	return STATUS_NOT_FOUND;
}

NTSTATUS GetProcessIdByProcessName(const wchar_t* ImageName, OUT HANDLE* OutPid )
{
	PSYSTEM_PROCESS_INFO pInfo = 0;
	PSYSTEM_PROCESS_INFO Buffer = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
		
	Buffer = (PSYSTEM_PROCESS_INFO)NQSI(SystemProcessInformation);
	if (!Buffer) 
		return STATUS_UNSUCCESSFUL;

	pInfo = Buffer;

	Status = STATUS_UNSUCCESSFUL;
	for (;;)
	{
		if (pInfo->ImageName.Buffer && StrICmp(ImageName, pInfo->ImageName.Buffer, TRUE))
		{
			//__db();
			*OutPid = pInfo->UniqueProcessId;
			Status = 0;
			break;
		}
		else if (pInfo->NextEntryOffset)
			pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
		else
			break;
	}

	KFree(Buffer);

	return Status;
}

#define IMAGE_FIRST_SECTION(NtHeader) (PIMAGE_SECTION_HEADER)(NtHeader + 1)
#define NT_HEADER(ModBase) (PIMAGE_NT_HEADERS)((ULONG64)(ModBase) + ((PIMAGE_DOS_HEADER)(ModBase))->e_lfanew)

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize)
{
	//get & enum sections
	PIMAGE_NT_HEADERS NT_Header = NT_HEADER(ModBase);
	PIMAGE_SECTION_HEADER Sect = IMAGE_FIRST_SECTION(NT_Header);

	for (PIMAGE_SECTION_HEADER pSect = Sect; pSect < Sect + NT_Header->FileHeader.NumberOfSections; pSect++)
	{
		//copy section name
		char SectName[9]; SectName[8] = 0;
		*(ULONG64*)&SectName[0] = *(ULONG64*)&pSect->Name[0];

		//check name
		if (StrICmp(Name, SectName, true))
		{
			//save size
			if (SectSize) {
				ULONG SSize = SizeAlign(max(pSect->Misc.VirtualSize, pSect->SizeOfRawData));
				*SectSize = SSize;
			}

			//ret full sect ptr
			return (PVOID)((ULONG64)ModBase + pSect->VirtualAddress);
		}
	}

	//no section
	return nullptr;
}

bool readByte(PVOID addr, UCHAR* ret)
{
	*ret = *(volatile char*)addr;
	return true;
}

//find pattern utils
#define InRange(x, a, b) (x >= a && x <= b) 
#define GetBits(x) (InRange(x, '0', '9') ? (x - '0') : (InRange(x, 'a', 'z') ? ((x - 'a') + 0xA) : ((x - 'A') + 0xA)) )
#define GetByte(x) ((UCHAR)(GetBits(x[0]) << 4 | GetBits(x[1])))

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern)
{
	if (!ModBase) return nullptr;

//get sect range
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)FindSection(ModBase, SectName, &SectSize);
	PUCHAR ModuleEnd = ModuleStart + SectSize;

	if (!ModuleStart) return nullptr;

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	if (*Pattern == '\0')
		CurPatt++;

	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');

		//hp(ModuleStart);
		UCHAR byte1;
		if (!readByte(ModuleStart, &byte1)) {
			auto addr2 = (u64)ModuleStart;
			addr2 &= 0xFFFFFFFFFFFFF000;
			addr2 += 0xFFF;
			ModuleStart = (PUCHAR)addr2;
			//sp("123");
			goto Skip;
		}

		if (SkipByte || byte1 == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			if (SkipByte)
				CurPatt += 2;
			else
				CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
		Skip:
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	//failed
	return nullptr;
}

PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern)
{
	//get sect range
	ULONG SectSize;
	PUCHAR ModuleStart = (PUCHAR)Start;
	PUCHAR ModuleEnd = ModuleStart + size;

	//scan pattern main
	PUCHAR FirstMatch = nullptr;
	const char* CurPatt = Pattern;
	if (*Pattern == '\0')
		CurPatt++;

	for (; ModuleStart < ModuleEnd; ++ModuleStart)
	{
		bool SkipByte = (*CurPatt == '\?');

		//hp(ModuleStart);
		UCHAR byte1;
		if (!readByte(ModuleStart, &byte1)) {
			auto addr2 = (u64)ModuleStart;
			addr2 &= 0xFFFFFFFFFFFFF000;
			addr2 += 0xFFF;
			ModuleStart = (PUCHAR)addr2;
			//sp("123");
			goto Skip;
		}

		if (SkipByte || byte1 == GetByte(CurPatt)) {
			if (!FirstMatch) FirstMatch = ModuleStart;
			SkipByte ? CurPatt += 2 : CurPatt += 3;
			if (CurPatt[-1] == 0) return FirstMatch;
		}

		else if (FirstMatch) {
			ModuleStart = FirstMatch;
		Skip:
			FirstMatch = nullptr;
			CurPatt = Pattern;
		}
	}

	//failed
	return nullptr;
}

PETHREAD LookupProcessThread(IN PEPROCESS pProcess)
{
	if (!pProcess)
		return 0;

	NTSTATUS status = STATUS_SUCCESS;
	PETHREAD thr = 0;
	HANDLE pid = ImpCall(PsGetProcessId, pProcess);
	auto Buf = NQSI(SystemProcessInformation);
	PSYSTEM_PROCESS_INFO pInfo = (PSYSTEM_PROCESS_INFO)Buf;

	// Find target thread	
	status = STATUS_NOT_FOUND;
	for (;;)
	{
		if (pInfo->UniqueProcessId == pid)
		{
			status = STATUS_SUCCESS;
			break;
		}
		else if (pInfo->NextEntryOffset)
			pInfo = (PSYSTEM_PROCESS_INFO)((PUCHAR)pInfo + pInfo->NextEntryOffset);
		else
			break;
	}

	status = STATUS_NOT_FOUND;

	// Get first thread
	for (ULONG i = 0; i < pInfo->NumberOfThreads; i++)
	{
		// Skip current thread
		if (/*pInfo->Threads[i].WaitReason == Suspended ||
			pInfo->Threads[i].ThreadState == 5 ||*/
			pInfo->Threads[i].ClientId.UniqueThread == ImpCall(PsGetCurrentThreadId))
		{
			continue;
		}

		status = ImpCall(PsLookupThreadByThreadId, pInfo->Threads[i].ClientId.UniqueThread, &thr);

		break;
	}

	KFree(Buf);

	return thr;

}


//NTSTATUS CopyPhysics(void* Dst, const void* PhySics, size_t _MaxCount)
//{
//	MM_COPY_ADDRESS copyaddr;
//	copyaddr.PhysicalAddress.QuadPart = (LONGLONG)PhySics;
//	SIZE_T copyed = 0;
//	return MmCopyMemory(Dst, copyaddr, _MaxCount, MM_COPY_MEMORY_PHYSICAL, &copyed);
//}


//void Log2File(const char* format, ...)
//{	
//	char msg[1024] = "";
//	va_list vl;
//	va_start(vl, format);
//	const int n = _vsnprintf(msg, sizeof(msg) / sizeof(char), format, vl);
//	msg[n] = '\0';
//	va_end(vl);
//	va_end(format);
//	UNICODE_STRING FileName;
//	OBJECT_ATTRIBUTES objAttr;
//	RtlInitUnicodeString(&FileName, L"\\DosDevices\\C:\\PPEngine.log");
//	InitializeObjectAttributes(&objAttr, &FileName,
//		OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE,
//		NULL, NULL);
//	if (KeGetCurrentIrql() != PASSIVE_LEVEL)
//	{
//		return;
//	}
//	HANDLE handle;
//	IO_STATUS_BLOCK ioStatusBlock;
//	NTSTATUS ntstatus = ZwCreateFile(&handle,
//		FILE_APPEND_DATA,
//		&objAttr, &ioStatusBlock, NULL,
//		FILE_ATTRIBUTE_NORMAL,
//		FILE_SHARE_WRITE | FILE_SHARE_READ,
//		FILE_OPEN_IF,
//		FILE_SYNCHRONOUS_IO_NONALERT,
//		NULL, 0);
//	if (NT_SUCCESS(ntstatus))
//	{
//		size_t cb;
//		ntstatus = RtlStringCbLengthA(msg, sizeof(msg), &cb);
//		if (NT_SUCCESS(ntstatus))
//			ZwWriteFile(handle, NULL, NULL, NULL, &ioStatusBlock, msg, (ULONG)cb, NULL, NULL);
//		ZwClose(handle);
//	}
//}

ULONG g_dwBuildNumber = 0;
ULONG GetWinVer() 
{
	if (!g_dwBuildNumber)
	{
		ImpCall(PsGetVersion, 0, 0, &g_dwBuildNumber, 0);
	}	
	return g_dwBuildNumber;
}

typedef struct _SYSTEM_KERNEL_DEBUGGER_INFORMATION
{
	BOOLEAN DebuggerEnabled;
	BOOLEAN DebuggerNotPresent;
} SYSTEM_KERNEL_DEBUGGER_INFORMATION, * PSYSTEM_KERNEL_DEBUGGER_INFORMATION;

BOOLEAN IsKernelDebuggerPresent()
{
	SYSTEM_KERNEL_DEBUGGER_INFORMATION DebuggerInfo;
	ULONG RetLen = 0;
	ImpCall(ZwQuerySystemInformation, SystemKernelDebuggerInformation, &DebuggerInfo, 8, &RetLen);

	return !DebuggerInfo.DebuggerNotPresent;
}

PVOID GetCurrentProcessModule(const char* ModName, ULONG* ModSize, bool force64)
{
	auto Process = ImpCall(IoGetCurrentProcess);

	PPEB32 pPeb32 = (PPEB32)ImpCall(PsGetProcessWow64Process,Process);

	if (pPeb32 && !force64)
	{
		if (!pPeb32->Ldr)
			return nullptr;

		for (PLIST_ENTRY32 pListEntry = (PLIST_ENTRY32)((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList.Flink;
			pListEntry != &((PPEB_LDR_DATA32)pPeb32->Ldr)->InLoadOrderModuleList;
			pListEntry = (PLIST_ENTRY32)pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY32 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY32, InLoadOrderLinks);

			if (StrICmp(ModName, (PWCH)pEntry->BaseDllName.Buffer, false))
			{
				if (ModSize)
				{
					*ModSize = pEntry->SizeOfImage;
				}

				return (PVOID)pEntry->DllBase;
			}
		}
	}
	else
	{
		PPEB64 PEB = ImpCall(PsGetProcessPeb, Process);
		if (!PEB || !PEB->Ldr)
			return nullptr;

		for (PLIST_ENTRY pListEntry = (PLIST_ENTRY)((PPEB_LDR_DATA64)(PEB->Ldr))->InLoadOrderModuleList.Flink;
			pListEntry != (PLIST_ENTRY)&((PPEB_LDR_DATA64)(PEB->Ldr))->InLoadOrderModuleList;
			pListEntry = pListEntry->Flink)
		{
			PLDR_DATA_TABLE_ENTRY64 pEntry = CONTAINING_RECORD(pListEntry, LDR_DATA_TABLE_ENTRY64, InLoadOrderLinks);

			if (StrICmp(ModName, pEntry->BaseDllName.Buffer, false))
			{
				if (ModSize)
				{
					*ModSize = pEntry->SizeOfImage;
				}

				return (PVOID)pEntry->DllBase;
			}
		}
	}

	return nullptr;
}

PVOID NQSI(SYSTEM_INFORMATION_CLASS Class)
{
	ULONG ret_size = 0;
	ImpCall(ZwQuerySystemInformation, Class, 0, 0, &ret_size);

	NTSTATUS status = 0;
	PVOID pInfo = 0;
	do
	{
		if (pInfo) KFree(pInfo);

		pInfo = KAlloc(ret_size);
		status = ImpCall(ZwQuerySystemInformation, Class, pInfo, ret_size, &ret_size);
	} while (status == STATUS_BUFFER_TOO_SMALL);

	return pInfo;
}




PVOID GetUserProcessModule(DWORD pid, const wchar_t* ModName)
{
	OperationData op;
	op.Module.ModName = ModName;// L"user32.dll";
	op.Process.Id = pid;
	auto status = Dispatch::GetModuleBase(&op);
	if (status)
		return 0;

	return op.Module.BaseAddress;
}

PEPROCESS GetUserProcessModule(const wchar_t* ProcessName, const wchar_t* ModName, __notnull pv* OutModBase)
{
	HANDLE Pid = 0;
	GetProcessIdByProcessName(ProcessName, &Pid);
	if (!Pid)
		return 0;

	OperationData op;
	op.Module.ModName = ModName;// L"user32.dll";
	op.Process.Id = (DWORD)Pid;
	auto status = Dispatch::GetModuleBase(&op);
	if (status)
		return 0;

	*OutModBase = op.Module.BaseAddress;

	PEPROCESS TargetProcess = 0;
	if (ImpCall(PsLookupProcessByProcessId, Pid, &TargetProcess))
		return 0;

	ImpCall(ObfDereferenceObject, TargetProcess);

	return TargetProcess;
}

NTSTATUS NTQM(PVOID UAddr, PMEMORY_BASIC_INFORMATION mbi)
{
	if (!mbi)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = 0;

	//if (ImpCall(ExGetPreviousMode) == UserMode)
	//{
	//	PMEMORY_BASIC_INFORMATION UserMbi = (PMEMORY_BASIC_INFORMATION)UAlloc(0x1000);
	//	status = ImpCall(ZwQueryVirtualMemory, (HANDLE)-1, (pv)((u64)UAddr & ~0xFFF), MemoryBasicInformation,
	//		UserMbi, sizeof(MEMORY_BASIC_INFORMATION), 0);
	//
	//	*mbi = *UserMbi;
	//
	//	UFree(UserMbi);
	//}
	//else
	{
		status = ImpCall(ZwQueryVirtualMemory, (HANDLE)-1, (pv)((u64)UAddr & ~0xFFF), MemoryBasicInformation,
			mbi, sizeof(MEMORY_BASIC_INFORMATION), 0);
	}

	if (status != 0)
		memset(mbi, 0, sizeof(*mbi));

	return status;
}

NTSTATUS ReadFile(IN const wchar_t* FileName, OUT char** DataFreeByCaller, OUT SIZE_T* DataSize)
{
	HANDLE hFile = NULL;
	IO_STATUS_BLOCK sb = { 0 };
	NTSTATUS status = 0;
	LARGE_INTEGER Offset = { 0 };
	OBJECT_ATTRIBUTES object_attr = { 0 };
	//ANSI_STRING anFilePath = { 0 };
	UNICODE_STRING unFilePathName = { 0 };
	FILE_STANDARD_INFORMATION fsi = { 0 };
	LARGE_INTEGER Size = { 0 };

	ImpCall(RtlInitUnicodeString, &unFilePathName, FileName);
	//status = RtlAnsiStringToUnicodeString(&unFilePathName, &anFilePath, TRUE);
	//if (!NT_SUCCESS(status))
	//{
	//	return status;
	//}

	InitializeObjectAttributes(&object_attr, &unFilePathName, OBJ_CASE_INSENSITIVE, NULL, NULL);
	status = ImpCall(ZwCreateFile, &hFile, GENERIC_READ, &object_attr, &sb, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ,
		FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE, NULL, 0);
	if (!NT_SUCCESS(status))
	{
		return status;
	}

	// 获取文件大小
	memset(&sb, 0, sizeof(sb));
	status = ImpCall(ZwQueryInformationFile, hFile, &sb, &fsi, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation);
	if (!NT_SUCCESS(status))
	{
		ImpCall(ZwClose, hFile);
		return status;
	}
	Size.QuadPart = fsi.EndOfFile.QuadPart;

	// 申请内存
	*DataFreeByCaller = (CHAR*)KAlloc(Size.QuadPart);
	if (*DataFreeByCaller == NULL)
	{
		ImpCall(ZwClose, hFile);
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	// 读文件
	status = ImpCall(ZwReadFile, hFile, NULL, NULL, NULL, &sb, (PVOID)*DataFreeByCaller, (ULONG)Size.QuadPart, &Offset, NULL);
	if (!NT_SUCCESS(status))
	{
		KFree(*DataFreeByCaller);
		*DataFreeByCaller = 0;
		return status;
	}

	if (DataSize)
		*DataSize = Size.QuadPart;
	return ImpCall(ZwClose, hFile);
}

bool DeleteFile(PUNICODE_STRING Path)
{

	HANDLE hFile = NULL;
	OBJECT_ATTRIBUTES obj = { 0 };
	IO_STATUS_BLOCK IoStatck = { 0 };
	InitializeObjectAttributes(&obj, Path, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL);

	NTSTATUS NtStatus = ImpCall(ZwCreateFile, &hFile, FILE_READ_ACCESS, &obj, &IoStatck, NULL,
		FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, NULL);
	if (!NT_SUCCESS(NtStatus))
		return FALSE;

	PFILE_OBJECT FileObject = NULL;
	NtStatus = ImpCall(ObReferenceObjectByHandle, hFile, FILE_ALL_ACCESS, *ImpGetVar(IoFileObjectType), KernelMode, (PVOID*)&FileObject, NULL);
	if (!NT_SUCCESS(NtStatus))
	{
		ImpCall(ZwClose, hFile);
		return FALSE;
	}
	ImpCall(ZwClose, hFile);

	FileObject->DeletePending = 0;
	FileObject->DeleteAccess = 1;
	FileObject->SharedDelete = 1;
	FileObject->SectionObjectPointer->DataSectionObject = NULL;
	FileObject->SectionObjectPointer->ImageSectionObject = NULL;
	FileObject->SectionObjectPointer->SharedCacheMap = NULL;
	NtStatus = ImpCall(ZwDeleteFile, &obj);
	ObDeref(FileObject);
	if (!NT_SUCCESS(NtStatus))
	{
		return FALSE;
	}
	return TRUE;
}

NTSTATUS WriteFile(PUNICODE_STRING filePath, PVOID data, ULONG length)
{
	NTSTATUS status;
	HANDLE fileHandle;
	OBJECT_ATTRIBUTES objAttr;
	IO_STATUS_BLOCK ioStatusBlock;

	// Initialize the object attributes to open the file
	InitializeObjectAttributes(&objAttr, filePath, OBJ_CASE_INSENSITIVE, NULL, NULL);

	// Open the file
	status = ZwCreateFile(&fileHandle, GENERIC_WRITE, &objAttr, &ioStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, 0, FILE_OVERWRITE_IF, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);

	if (!NT_SUCCESS(status))
	{
		// File open failed
		return status;
	}

	// Write the data to the file
	status = ZwWriteFile(fileHandle, NULL, NULL, NULL, &ioStatusBlock, data, length, NULL, NULL);

	if (!NT_SUCCESS(status))
	{
		// Write operation failed
		ZwClose(fileHandle);
		return status;
	}

	// Close the file handle
	ZwClose(fileHandle);

	return STATUS_SUCCESS;
}

bool IsValidFileObject(PFILE_OBJECT FileObject)
{
	if (!IsValid(FileObject))
		return false;

	if (FileObject->Type != 5)
		return false;

	return true;
}

//Data free by caller, ret = C:\Users\Pipi\Desktop\1.exe 
POBJECT_NAME_INFORMATION GetFileNameInfo(PFILE_OBJECT FileObject)
{
	if (!IsValidFileObject(FileObject))
		return 0;

	POBJECT_NAME_INFORMATION ObjectNameInformation = 0;

	ImpCall(IoQueryFileDosDeviceName, FileObject, &ObjectNameInformation);

	if (ObjectNameInformation)
		*(PWCH)((u64)ObjectNameInformation->Name.Buffer + ObjectNameInformation->Name.Length) = L'\0';

	return ObjectNameInformation;
}

typedef NTSTATUS (NTAPI* _PsSuspendThread)(IN PETHREAD Thread, OUT PULONG PreviousSuspendCount OPTIONAL);
_PsSuspendThread PsSuspendThread = 0;

typedef u64 (__fastcall* _KeResumeThread)(IN PETHREAD Thread, IN ULONG One);
_KeResumeThread KeResumeThread = 0;

void InitSuspendResumeThread()
{
	auto rva =
		FindPatternSect(EPtr(::NtBase), E("PAGE"), E("F7 ? 74 00 00 20 00 75 ? 33 D2 48 8B ? E8"));
	PsSuspendThread = (_PsSuspendThread)RVA(rva + 14, 5);

	auto rva2 =
		FindPatternSect(EPtr(::NtBase), E("PAGE"), E("F7 ? 74 00 00 20 00 75 ? 48 8B ? E8"));
	if (rva2)
	{
		KeResumeThread = (_KeResumeThread)RVA(rva2 + 12, 5);
	}
	else
	{
		rva2 = FindPatternSect(EPtr(::NtBase), E(".text"), E("F7 ? 74 00 00 20 00 75 ? BA 01 00 00 00 48 8B ? E8"));
		if (!rva2)
			__db();
		KeResumeThread = (_KeResumeThread)RVA(rva2 + 17, 5);
	}
}

NTSTATUS SuspendThread(PETHREAD Thread)
{
	if (!Thread)
		return STATUS_NOT_FOUND;
	
	if (!PsSuspendThread || !KeResumeThread)
	{
		InitSuspendResumeThread();
	}

	if (!PsSuspendThread)
		return STATUS_PROCEDURE_NOT_FOUND;

	return PsSuspendThread(Thread, 0);
}

NTSTATUS ResumeThread(PETHREAD Thread)
{
	if (!Thread)
		return STATUS_NOT_FOUND;

	if (!PsSuspendThread || !KeResumeThread)
	{
		InitSuspendResumeThread();
	}

	if (!KeResumeThread)
		return STATUS_PROCEDURE_NOT_FOUND;

	KeResumeThread(Thread, 1);

	return 0;
}



