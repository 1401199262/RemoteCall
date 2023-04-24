#pragma once
#include "UsermodeCallback.h"

typedef struct _SET_CONTEXT_CALL_INFORMATION SET_CONTEXT_CALL_INFORMATION, * PSET_CONTEXT_CALL_INFORMATION;

// executed on the context of target process, irql = 0. 
using PreUserCall =  void(*)(PSET_CONTEXT_CALL_INFORMATION);
using PostUserCall = void(*)(PSET_CONTEXT_CALL_INFORMATION);

struct _SET_CONTEXT_CALL_INFORMATION
{
	PETHREAD TargetThread;
	PVOID UserFunction;
	u64 ReturnVal;
	KEVENT Event;
	PreUserCall PreCallKernelRoutine;
	PostUserCall PostCallKernelRoutine;

	SIZE_T ParamCnt;
	struct
	{
		u64 AsU64;
	}Param[1];

};


class SetCtxCall
{
private:


	u64 CommuFunction = 0;
	PUCHAR CallRet = 0;
	
	UsermodeCallback CtxUserCall;
	bool bUserCallInit = false;

	bool bInitCommu = false;
	PSET_CONTEXT_CALL_INFORMATION CallInfo = 0;


	static ULONG64 SANITIZE_VA(IN ULONG64 VirtualAddress, IN USHORT Segment, IN KPROCESSOR_MODE PreviousMode);

	static VOID PspGetContext(IN PKTRAP_FRAME TrapFrame, IN PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, IN OUT PCONTEXT ContextRecord);

	static VOID PspSetContext(OUT PKTRAP_FRAME TrapFrame, OUT PKNONVOLATILE_CONTEXT_POINTERS ContextPointers, IN PCONTEXT ContextRecord, KPROCESSOR_MODE PreviousMode);

	static PKTRAP_FRAME PspGetBaseTrapFrame(PETHREAD Thread);

	static NTSTATUS HkCommunicate(u64 a1);

	static VOID SetCtxApcCallback(PRKAPC Apc, PKNORMAL_ROUTINE* NormalRoutine, PVOID* NormalContext, PVOID* SystemArgument1, PVOID* SystemArgument2);

	NTSTATUS QueueUserApc(PSET_CONTEXT_CALL_INFORMATION CallInfo);
public:


	NTSTATUS Call();

};

extern class SetCtxCall CtxCall;
