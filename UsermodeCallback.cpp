#include "global.h"
#include "UsermodeCallback.h"






void UsermodeCallback::Init() {
	//KiCallUserMode = (KiCallUserModefn)0xfffff801735c4ac0;
	//MmCreateKernelStack = (MmCreateKernelStackfn)0xfffff8017346c210;
	//MmDeleteKernelStack = (MmDeleteKernelStackfn)0xfffff8017346d1e0;


	ContextUser = (CONTEXT*)UAlloc(sizeof(CONTEXT), PAGE_READWRITE, true);


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
