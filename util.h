#pragma once

NTSTATUS getKernelModuleByName(const char* moduleName, PVOID* moduleStart, size_t* moduleSize = 0);

NTSTATUS GetProcessIdByProcessName(const wchar_t* ImageName, OUT HANDLE* OutPid);

PVOID FindSection(PVOID ModBase, const char* Name, PULONG SectSize);

PUCHAR FindPatternSect(PVOID ModBase, const char* SectName, const char* Pattern);

PUCHAR FindPatternRange(PVOID Start, u32 size, const char* Pattern);

PETHREAD LookupProcessThread(IN PEPROCESS pProcess);

//NTSTATUS RtlSuperCopyMemory(IN VOID* Dst, IN CONST VOID* Src, IN ULONG Length);

//NTSTATUS RtlSuperWriteMemoryPipi(IN VOID* Dst, IN CONST VOID* Src, IN ULONG Length);

void Log2File(const char* format, ...);

//dwBuildNumber
ULONG GetWinVer();

BOOLEAN IsKernelDebuggerPresent();

PVOID GetProcAddress(PVOID ModBase, const char* Name);

PVOID GetCurrentProcessModule(const char* ModName, ULONG* ModSize = 0, bool force64 = 1);

PVOID NQSI(SYSTEM_INFORMATION_CLASS Class);

PVOID GetUserProcessModule(DWORD pid, const wchar_t* ModName);

PEPROCESS GetUserProcessModule(const wchar_t* ProcessName, const wchar_t* ModName, __notnull pv* OutModBase);

PEPROCESS GetEpro(HANDLE pid);

inl BOOLEAN IsProcessExit(PEPROCESS epro);

NTSTATUS ReadFile(IN const wchar_t* FileName, OUT char** DataFreeByCaller, OUT SIZE_T* DataSize);

bool DeleteFile(PUNICODE_STRING Path);

NTSTATUS WriteFile(PUNICODE_STRING filePath, PVOID data, ULONG length);

bool IsValidFileObject(PFILE_OBJECT FileObject);

POBJECT_NAME_INFORMATION GetFileNameInfo(PFILE_OBJECT FileObject);

#define LOCK(Lock) while (_InterlockedCompareExchange64(&Lock, 1, 0) == 1){;}

#define UNLOCK(Lock) (InterlockedExchange64(&Lock, 0))

#define SizeAlign(Size) ((Size + 0xFFF) & 0xFFFFFFFFFFFFF000)

inl void MemZero(PVOID Ptr, SIZE_T Size, UCHAR Filling = 0)
{
	__stosb((PUCHAR)Ptr, Filling, Size);
}

inl void MemCpy(PVOID Destination, PVOID Source, SIZE_T Count)
{
	__movsb((PUCHAR)Destination, (PUCHAR)Source, Count);
}

inl PVOID UAlloc(ULONG Size, ULONG Protect = PAGE_READWRITE, bool load = true)
{
	PVOID AllocBase = nullptr; SIZE_T SizeUL = SizeAlign(Size);	
#define LOCK_VM_IN_RAM 2
#define LOCK_VM_IN_WORKING_SET 1
	if (!ImpCall(ZwAllocateVirtualMemory, ZwCurrentProcess(), &AllocBase, 0, &SizeUL, MEM_COMMIT, Protect)) {
		//ZwLockVirtualMemory(ZwCurrentProcess(), &AllocBase, &SizeUL, LOCK_VM_IN_WORKING_SET | LOCK_VM_IN_RAM);
		if (load)
			MemZero(AllocBase, SizeUL);
	}
	return AllocBase;
}

inl DWORD UProtect(PVOID Address, ULONG Size, ULONG Protect)
{
	SIZE_T SizeUL = Size;
	u32 OldPro = 0;
	ImpCall(ZwProtectVirtualMemory, ZwCurrentProcess(), &Address, &SizeUL, Protect, &OldPro);
	return OldPro;
}

inl void UFree(PVOID Ptr)
{
	SIZE_T SizeUL = 0;
	ImpCall(ZwFreeVirtualMemory, ZwCurrentProcess(), &Ptr, &SizeUL, MEM_RELEASE);
}

//help to debug
extern volatile u64 LastAllocation;
extern volatile u64 LastAllocationAddress;


//kernel memory utils
inl PVOID KAlloc(u64 Size, bool exec = false, bool PagedPool = false)
{
	PVOID Buff = ImpCall(ExAllocatePoolWithTag,
		PagedPool ? POOL_TYPE::PagedPool : (exec ? NonPagedPool : NonPagedPoolNx),
		Size, GetRandomPoolTag());
	memset(Buff, 0, Size);

	LastAllocation = (u64)Buff;
	LastAllocationAddress = (u64)_ReturnAddress();
	return Buff;
}

inl void KFree(PVOID Ptr)
{
	if(Ptr)
		ImpCall(ExFreePoolWithTag, Ptr, 0);
}

inl PVOID GetModuleHandle(const char* ModName)
{
	return GetCurrentProcessModule(ModName);
}

inl KAPC_STATE KeStackAttach(PEPROCESS process)
{
	KAPC_STATE kapc;
	ImpCall(KeStackAttachProcess, process, &kapc);
	return kapc;
}

inl void KeStackDetach(KAPC_STATE* kapc)
{
	ImpCall(KeUnstackDetachProcess, kapc);
}

inl KPROCESSOR_MODE ExSetPreviousMode(KPROCESSOR_MODE NewMode, PETHREAD Thread = (PETHREAD)__readgsqword(0x188))
{
	auto ret = *(u8*)((u64)Thread + 0x232);
	*(u8*)((u64)Thread + 0x232) = NewMode;
	return ret;
}

inl KTRAP_FRAME* PsGetTrapFrame(PETHREAD Thread = (PETHREAD)__readgsqword(0x188))
{
	return *(KTRAP_FRAME**)((ULONG64)Thread + 0x90);
}

inl void PsSetTrapFrame(PETHREAD Thread, KTRAP_FRAME* tf)
{
	*(KTRAP_FRAME**)((ULONG64)Thread + 0x90) = tf;
}

inl PEPROCESS GetEpro(HANDLE pid)
{
	PEPROCESS epro = 0;
	ImpCall(PsLookupProcessByProcessId, pid, &epro);
	return epro;
}

inl BOOLEAN IsProcessExit(PEPROCESS epro)
{
	if (!epro)
	{
		__dbgdb();
		return TRUE;
	}

	return ImpCall(PsGetProcessExitStatus, epro) != STATUS_PENDING;
}

#define ObDeref ObfDeref

inl void ObfDeref(PVOID Obj)
{
	if(Obj)
		ImpCall(ObfDereferenceObject, Obj);
}

inl void KSleep(LONG milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(10000 * milliseconds); // convert milliseconds to 100 nanosecond intervals
	ImpCall(KeDelayExecutionThread, KernelMode, FALSE, &interval);
}



template <class T>
inl bool IsCanonicalAddress(T address)
{
	u64 addr = *(u64*)&address;

	if (addr <= 0x1000)
		return false;

	if (
		((addr >= 0xFFFF800000000000) && (addr <= 0xFFFFFFFFFFFFFFFF)) ||
		((addr >= 0) && (addr <= 0x7FFFFFFFFFFF)) 		
		)
	{
		return true;
	}

	return false;
}

inl BOOLEAN IsValid(pv addr)
{
	if ((u64)addr <= 0x1000)
		return false;

	if (!IsCanonicalAddress(addr))
		return false;

	return ImpCall(MmIsAddressValid, addr);
}

inl BOOLEAN IsValid(u64 addr)
{
	if (addr < 0x1000)
		return false;
	return ImpCall(MmIsAddressValid, (pv)addr);
}

NTSTATUS NTQM(PVOID UAddr, PMEMORY_BASIC_INFORMATION mbi);

inl DECLSPEC_NORETURN VOID BugCheck(u32 Line)
{
	ImpCall(KeBugCheck, Line);
}

#define GetTickCount64 KeQueryInterruptTime

extern ULONG g_dwBuildNumber;

