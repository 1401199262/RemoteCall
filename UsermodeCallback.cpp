#include "global.h"
#include "UsermodeCallback.h"






void UsermodeCallback::Init() {
	//KiCallUserMode = (KiCallUserModefn)0xfffff801735c4ac0;
	//MmCreateKernelStack = (MmCreateKernelStackfn)0xfffff8017346c210;
	//MmDeleteKernelStack = (MmDeleteKernelStackfn)0xfffff8017346d1e0;


	ContextUser = (CONTEXT*)UAlloc(sizeof(CONTEXT), PAGE_READWRITE);
	ULONG NtdllSize; auto NtdllBase = GetCurrentProcessModule(E("ntdll.dll"), &NtdllSize);
	NtContinue = GetProcAddress(NtdllBase, "NtContinue");

	CFG_CALL_TARGET_INFO TargetInfo[1];
	TargetInfo[0].Flags = 0x00000001;
	TargetInfo[0].Offset = (ULONG_PTR)((ULONG64)NtContinue - (ULONG64)NtdllBase);

	MEMORY_RANGE_ENTRY RangeEntry;
	RangeEntry.VirtualAddress = NtdllBase;
	RangeEntry.NumberOfBytes = NtdllSize;

	VM_INFORMATION VMInfo;
	VMInfo.NumberOfOffsets = 1;
	VMInfo.MustBeZero = 0;
	VMInfo.TargetsProcessed = &VMInfo.ExpectedFileOffset;

	VMInfo.CallTargets = &TargetInfo[0];
	VMInfo.Section.Section = 0;
	VMInfo.Section.Data = 0;
	VMInfo.ExpectedFileOffset = 0;

	/*
	*  FIX CFG  -- 
	 
		USER32!_fnDWORD:
		sub     rsp,58h
		mov     rax,rcx
		xor     ecx,ecx
		mov     dword ptr [rsp+38h],ecx
		mov     qword ptr [rsp+40h],rcx
		mov     rdx,qword ptr [rax+20h]
		mov     r9,qword ptr [rax+18h]
		mov     r8,qword ptr [rax+10h]
		mov     rcx,qword ptr [rax]
		mov     qword ptr [rsp+20h],rdx
		mov     edx,dword ptr [rax+8]
		mov     rax,qword ptr [rax+28h]
		call    qword ptr [USER32!_guard_dispatch_icall_fptr (00007ffe`87599b10)]
	*/
	auto statusss = ImpCall(ZwSetInformationVirtualMemory, (HANDLE)-1, (VIRTUAL_MEMORY_INFORMATION_CLASS)2, 1, &RangeEntry, (PVOID)&VMInfo, 0x28);


	//__db();
	//MmCreateKernelStack = (pv)(RVA(FindPatternSect(KBase, (".text"), ("E8 ? ? ? ? 41 83 CF 04")), 5));
	//ImpCall(DbgPrintEx, 0, 0, "MmCreateKernelStack %llx\n", MmCreateKernelStack);
	//__db();
	//MmDeleteKernelStack = (pv)(RVA(FindPatternSect(KBase, ("PAGE"), ("8B D5 E8 ? ? ? ? 48 8B 05 ? ? ? ? 48 05 ? ? ? ?")), 7));
	//ImpCall(DbgPrintEx, 0, 0, "MmDeleteKernelStack %llx\n", MmDeleteKernelStack);
	//__db();
	//KiCallUserMode = (pv)(RVA(FindPatternSect(KBase, ("PAGE"), ("4D 8D ? ? 48 8B 94 24 ? ? ? ? 48 8B 8C 24 ? ? ? ? E8 ? ? ? ?")), 25));
	//ImpCall(DbgPrintEx, 0, 0, "KiCallUserMode %llx\n", KiCallUserMode);
}


UsermodeCallback UserCallback;
