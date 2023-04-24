#pragma once


class UsermodeCallback {
private:
	CONTEXT* ContextUser;
	PVOID NtContinue;

	typedef struct _KSTACK_CONTROL {
		DWORD64 StackBase;
		DWORD64 StackLimit;
		DWORD64 PreviousStackBase;
		DWORD64 PreviousStackLimit;
		DWORD64 Spare0;
		DWORD64 PreviousInitialStack;
		DWORD64 ShadowStackControl[4];
	}KSTACK_CONTROL, * PKSTACK_CONTROL;

	typedef struct _MACHINE_FRAME {
		ULONG64 Rip;
		USHORT SegCs;
		USHORT Fill1[3];
		ULONG EFlags;
		ULONG Fill2;
		ULONG64 Rsp;
		USHORT SegSs;
		USHORT Fill3[3];
	} MACHINE_FRAME, * PMACHINE_FRAME;

	typedef struct _UCALLOUT_FRAME {
		ULONG64 P1Home;
		ULONG64 P2Home;
		ULONG64 P3Home;
		ULONG64 P4Home;
		PVOID Buffer;
		ULONG Length;
		ULONG ApiNumber;
		MACHINE_FRAME MachineFrame;
	} UCALLOUT_FRAME, * PUCALLOUT_FRAME;

#define STACK_ALIGN (16UI64)
#define STACK_ROUND (STACK_ALIGN - 1)
#define UCALLOUT_FRAME_LENGTH sizeof(UCALLOUT_FRAME)

	struct KEUSER_CALLBACK {
		ULONG64 Arg1;
		ULONG64 Arg2;
		ULONG64 Arg3;
		ULONG64 Arg4;
		ULONG64 Arg5;
		PVOID   Func;
	};

	typedef u64(NTAPI* MmCreateKernelStackfn)(u64, u64, u64);
	typedef u64(NTAPI* MmDeleteKernelStackfn)(u64, u64);
	typedef NTSTATUS(NTAPI* KiCallUserModefn)(
		PVOID* Outputbuffer,
		PULONG OutputLength,
		PKSTACK_CONTROL KSC,
		DWORD64 NewStackBase,
		DWORD64 KernelShadowStackBase,
		DWORD64 KernelShadowStackInitial
		);

	KiCallUserModefn KiCallUserMode = (KiCallUserModefn)0xfffff801735c4ac0;
	MmCreateKernelStackfn MmCreateKernelStack = (MmCreateKernelStackfn)0xfffff8017346c210;
	MmDeleteKernelStackfn MmDeleteKernelStack = (MmDeleteKernelStackfn)0xfffff8017346d1e0;

	//PVOID KiCallUserMode;
	//PVOID PspGetContextThreadInternal;


public:
	void Init();
	template<typename Ret = void*, typename A1 = void*, typename A2 = void*, typename A3 = void*, typename A4 = void*, typename A5 = void*, typename A6 = void*>
	u64 Call(PVOID Ptr, A1 a1 = 0, A2 a2 = 0, A3 a3 = 0, A4 a4 = 0, A5 a5 = 0, A6 a6 = 0)
	{
		*(vu64*)Ptr;

		ContextUser->Rcx = (ULONG64)a1;
		ContextUser->Rdx = (ULONG64)a2;
		ContextUser->R8 = (ULONG64)a3;
		ContextUser->R9 = (ULONG64)a4;

		auto TrapFrame = PsGetTrapFrame(KeGetCurrentThread());
		if (!TrapFrame)
		{
			// Stack walk and find trapframe, also set kthread.trapframe since KeUserCall use it. 
			//__dbgdb();
			//TrapFrame = StackWalkFindTrapFrame();
			//if (!TrapFrame)
				__db();
			//PsSetTrapFrame(KeGetCurrentThread(), TrapFrame);
		}

		ContextUser->Rsp = TrapFrame->Rsp - 0xF0;

		ContextUser->Rip = (ULONG64)Ptr;
		ContextUser->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		*(ULONG64*)(ContextUser->Rsp + 0x30) = (ULONG64)a6;

		KEUSER_CALLBACK UserData;
		UserData.Arg1 = (ULONG64)ContextUser;
		UserData.Arg5 = (ULONG64)a5;
		UserData.Arg2 = 0;
		UserData.Func = NtContinue;

		ImpCall(KeUserModeCallback, 2, &UserData, sizeof(UserData), (pv*)&UserData, (ULONG*)&UserData.Arg2);

		u64 ret = 0;
		if (IsValid(UserData.Arg1))
			ret = *(u64*)UserData.Arg1;

		return ret;
		//USER32!_fnDWORD+0x33:
		//xor     r8d,r8d
		//lea     rcx,[rsp+30h]
		//mov     qword ptr [rsp+30h],rax
		//lea     edx,[r8+18h]
		//call    qword ptr [USER32!_imp_NtCallbackReturn (00007ffe`87598790)]
		//add     rsp,58h
		//ret

	}

	NTSTATUS KeUserModeCall(
		IN ULONG ApiNumber,
		IN PVOID   InputBuffer,
		IN ULONG InputLength,
		OUT PVOID* OutputBuffer,
		IN PULONG OutputLength
	)
	{
		PKTRAP_FRAME TrapFrame;
		ULONG64 OldStack;
		NTSTATUS Status;
		ULONG Length;
		PUCALLOUT_FRAME CalloutFrame;

		auto CurrentThread = __readgsqword(0x188);
		*(UCHAR*)(CurrentThread + 0x2db) = *(UCHAR*)(CurrentThread + 0x2db) + 1; // CallbackNestingLevel++

		DWORD64 StackBase = (DWORD64)MmCreateKernelStack(FALSE, 0, 0);

		PKSTACK_CONTROL KSC = (PKSTACK_CONTROL)(StackBase - sizeof(KSTACK_CONTROL));
		KSC->StackBase = StackBase;
		KSC->StackLimit = StackBase - KERNEL_STACK_SIZE;
		KSC->PreviousStackBase = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x38);//KernelStack
		KSC->PreviousStackLimit = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x30);//StackLimit
		KSC->PreviousInitialStack = *(DWORD64*)((DWORD64)KeGetCurrentThread() + 0x28);//InitialStack
		memset(&KSC->ShadowStackControl, 0, 8*4);

		TrapFrame = PsGetTrapFrame(KeGetCurrentThread());
		OldStack = TrapFrame->Rsp;

		Length = ((InputLength + STACK_ROUND) & ~STACK_ROUND) + UCALLOUT_FRAME_LENGTH;
		CalloutFrame = (PUCALLOUT_FRAME)((OldStack - Length) & ~STACK_ROUND);
		memmove(&CalloutFrame[1], InputBuffer, InputLength);

		CalloutFrame->Buffer = &CalloutFrame[1];
		CalloutFrame->Length = InputLength;
		CalloutFrame->ApiNumber = ApiNumber;
		CalloutFrame->MachineFrame.Rsp = OldStack;
		CalloutFrame->MachineFrame.Rip = TrapFrame->Rip;

		TrapFrame->Rsp = (ULONG64)CalloutFrame;

		Status = KiCallUserMode(
			OutputBuffer,
			OutputLength,
			KSC,
			StackBase,
			0,
			0
		);

		*(UCHAR*)(CurrentThread + 0x2db) = *(UCHAR*)(CurrentThread + 0x2db) - 1; // CallbackNestingLevel--

		MmDeleteKernelStack(StackBase, FALSE);

		TrapFrame->Rsp = OldStack;
		return Status;

	}

	template<typename Ret = void*, typename A1 = void*, typename A2 = void*, typename A3 = void*, typename A4 = void*, typename A5 = void*, typename A6 = void*>
	u64 Call2(PVOID Ptr, A1 a1 = 0, A2 a2 = 0, A3 a3 = 0, A4 a4 = 0, A5 a5 = 0, A6 a6 = 0)
	{
		*(vu64*)Ptr;

		ContextUser->Rcx = (ULONG64)a1;
		ContextUser->Rdx = (ULONG64)a2;
		ContextUser->R8 = (ULONG64)a3;
		ContextUser->R9 = (ULONG64)a4;

		auto TrapFrame = PsGetTrapFrame(KeGetCurrentThread());
		if (!TrapFrame)
		{
			// Stack walk and find trapframe, also set kthread.trapframe since KeUserCall use it. 
			//__dbgdb();
			//TrapFrame = StackWalkFindTrapFrame();
			//if (!TrapFrame)
				__db();
			//PsSetTrapFrame(KeGetCurrentThread(), TrapFrame);
		}

		ContextUser->Rsp = TrapFrame->Rsp - 0xF8;

		ContextUser->Rip = (ULONG64)Ptr;
		ContextUser->ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
		*(ULONG64*)(ContextUser->Rsp + 0x30) = (ULONG64)a6;
		
		KEUSER_CALLBACK UserData;
		UserData.Arg1 = (ULONG64)ContextUser;
		UserData.Arg5 = (ULONG64)a5;
		UserData.Arg2 = 0;
		UserData.Func = NtContinue;

		KeUserModeCall( 2, &UserData, sizeof(UserData), (pv*)&UserData, (ULONG*)&UserData.Arg2);

		u64 ret = 0;
		if (IsValid(UserData.Arg1))
			ret = *(u64*)UserData.Arg1;

		return ret;
		//USER32!_fnDWORD+0x33:
		//xor     r8d,r8d
		//lea     rcx,[rsp+30h]
		//mov     qword ptr [rsp+30h],rax
		//lea     edx,[r8+18h]
		//call    qword ptr [USER32!_imp_NtCallbackReturn (00007ffe`87598790)]
		//add     rsp,58h
		//ret

	}

};

extern UsermodeCallback UserCallback;
