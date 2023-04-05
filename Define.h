#pragma once


typedef unsigned long long y64;
typedef unsigned long long u64;
typedef unsigned long long* pu64;
using i64 = __int64;
typedef volatile unsigned long long vu64;
typedef unsigned long u32;
typedef void* pv;
typedef void* pv64;
typedef unsigned short u16;
typedef unsigned char u8;
typedef unsigned char* pu8;
typedef unsigned long long QWORD;


#define __db __debugbreak

#ifdef dbgmode
#define dbgdb __db
#define __dbgdb dbgdb
#else
#define dbgdb() 
#define __dbgdb() 
#endif



#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))


#define PAGE_2MB_SIZE				0x200000
#define	CR3_FLAG_ALL_BITS			0xFFF0000000000FFF

typedef union _virt_addr_t
{
	ULONG64 value;
	struct
	{
		ULONG64 offset : 12;
		ULONG64 pt_index : 9;
		ULONG64 pd_index : 9;
		ULONG64 pdpt_index : 9;
		ULONG64 pml4_index : 9;
		ULONG64 reserved : 16;
	};
	struct
	{
		ULONG64 large_page_offset : 21;
	};
} virt_addr_t, * pvirt_addr_t;

typedef struct _CURDIR
{
	struct _UNICODE_STRING DosPath;                                         //0x0
	VOID* Handle;                                                           //0x10
} CURDIR, * PCURDIR;

union ThreadMiscFlags
{
	struct
	{
		ULONG AutoBoostActive : 1;                                        //0x74
		ULONG ReadyTransition : 1;                                        //0x74
		ULONG WaitNext : 1;                                               //0x74
		ULONG SystemAffinityActive : 1;                                   //0x74
		ULONG Alertable : 1;                                              //0x74
		ULONG UserStackWalkActive : 1;                                    //0x74
		ULONG ApcInterruptRequest : 1;                                    //0x74
		ULONG QuantumEndMigrate : 1;                                      //0x74
		ULONG UmsDirectedSwitchEnable : 1;                                //0x74
		ULONG TimerActive : 1;                                            //0x74
		ULONG SystemThread : 1;                                           //0x74
		ULONG ProcessDetachActive : 1;                                    //0x74
		ULONG CalloutActive : 1;                                          //0x74
		ULONG ScbReadyQueue : 1;                                          //0x74
		ULONG ApcQueueable : 1;                                           //0x74
		ULONG ReservedStackInUse : 1;                                     //0x74
		ULONG UmsPerformingSyscall : 1;                                   //0x74
		ULONG TimerSuspended : 1;                                         //0x74
		ULONG SuspendedWaitMode : 1;                                      //0x74
		ULONG SuspendSchedulerApcWait : 1;                                //0x74
		ULONG CetUserShadowStack : 1;                                     //0x74
		ULONG BypassProcessFreeze : 1;                                    //0x74
		ULONG Reserved : 10;                                              //0x74
	};
	LONG MiscFlags;                                                     //0x74
};

#define MemoryWorkingSetList 1
#define MemorySectionName 2
#define MemoryBasicVlmInformation 3
#define MemoryWorkingSetExList 4

typedef union _PSAPI_WORKING_SET_BLOCK {
	ULONG_PTR Flags;
	struct {
		ULONG_PTR Protection : 5;
		ULONG_PTR ShareCount : 3;
		ULONG_PTR Shared : 1;
		ULONG_PTR Reserved : 3;
#if defined(_WIN64)
		ULONG_PTR VirtualPage : 52;
#else
		ULONG_PTR VirtualPage : 20;
#endif
	};
} PSAPI_WORKING_SET_BLOCK, * PPSAPI_WORKING_SET_BLOCK;

typedef struct _PSAPI_WORKING_SET_INFORMATION {
	ULONG_PTR NumberOfEntries;
	PSAPI_WORKING_SET_BLOCK WorkingSetInfo[1];
} PSAPI_WORKING_SET_INFORMATION, * PPSAPI_WORKING_SET_INFORMATION;

typedef union _PSAPI_WORKING_SET_EX_BLOCK {
	ULONG_PTR Flags;
	union {
		struct {
			ULONG_PTR Valid : 1;
			ULONG_PTR ShareCount : 3;
			ULONG_PTR Win32Protection : 11;
			ULONG_PTR Shared : 1;
			ULONG_PTR Node : 6;
			ULONG_PTR Locked : 1;
			ULONG_PTR LargePage : 1;
			ULONG_PTR Reserved : 7;
			ULONG_PTR Bad : 1;

#if defined(_WIN64)
			ULONG_PTR ReservedUlong : 32;
#endif
		};
		struct {
			ULONG_PTR Valid : 1;            // Valid = 0 in this format.
			ULONG_PTR Reserved0 : 14;
			ULONG_PTR Shared : 1;
			ULONG_PTR Reserved1 : 15;
			ULONG_PTR Bad : 1;

#if defined(_WIN64)
			ULONG_PTR ReservedUlong : 32;
#endif
		} Invalid;
	};
} PSAPI_WORKING_SET_EX_BLOCK, * PPSAPI_WORKING_SET_EX_BLOCK;

typedef struct _PSAPI_WORKING_SET_EX_INFORMATION {
	PVOID VirtualAddress;
	PSAPI_WORKING_SET_EX_BLOCK VirtualAttributes;
} PSAPI_WORKING_SET_EX_INFORMATION, * PPSAPI_WORKING_SET_EX_INFORMATION;

typedef enum _KAPC_ENVIRONMENT
{
	OriginalApcEnvironment,
	AttachedApcEnvironment,
	CurrentApcEnvironment,
	InsertApcEnvironment
} KAPC_ENVIRONMENT, * PKAPC_ENVIRONMENT;

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKRUNDOWN_ROUTINE)(PRKAPC Apc);

typedef VOID(NTAPI* PKNORMAL_ROUTINE)(
	PVOID NormalContext,
	PVOID SystemArgument1,
	PVOID SystemArgument2
	);

typedef VOID(NTAPI* PKKERNEL_ROUTINE)(
	PRKAPC Apc,
	PKNORMAL_ROUTINE* NormalRoutine,
	PVOID* NormalContext,
	PVOID* SystemArgument1,
	PVOID* SystemArgument2
	);

typedef struct _RTL_USER_PROCESS_PARAMETERS
{
	ULONG MaximumLength;                                                    //0x0
	ULONG Length;                                                           //0x4
	ULONG Flags;                                                            //0x8
	ULONG DebugFlags;                                                       //0xc
	VOID* ConsoleHandle;                                                    //0x10
	ULONG ConsoleFlags;                                                     //0x18
	VOID* StandardInput;                                                    //0x20
	VOID* StandardOutput;                                                   //0x28
	VOID* StandardError;                                                    //0x30
	struct _CURDIR CurrentDirectory;                                        //0x38
	struct _UNICODE_STRING DllPath;                                         //0x50
	struct _UNICODE_STRING ImagePathName;                                   //0x60
	struct _UNICODE_STRING CommandLine;                                     //0x70
	VOID* Environment;                                                      //0x80
	ULONG StartingX;                                                        //0x88
	ULONG StartingY;                                                        //0x8c
	ULONG CountX;                                                           //0x90
	ULONG CountY;                                                           //0x94
	ULONG CountCharsX;                                                      //0x98
	ULONG CountCharsY;                                                      //0x9c
	ULONG FillAttribute;                                                    //0xa0
	ULONG WindowFlags;                                                      //0xa4
	ULONG ShowWindowFlags;                                                  //0xa8
	struct _UNICODE_STRING WindowTitle;                                     //0xb0
	struct _UNICODE_STRING DesktopInfo;                                     //0xc0
	struct _UNICODE_STRING ShellInfo;                                       //0xd0
	struct _UNICODE_STRING RuntimeData;                                     //0xe0
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;

typedef struct _PEB32 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG/*PPEB_LDR_DATA32*/ Ldr;
	ULONG ProcessParameters;
} PEB32, * PPEB32;

typedef struct _PEB64 {
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR Spare;
	UCHAR Padding0[4];
	ULONG64 Mutant;
	ULONG64 ImageBaseAddress;
	ULONG64/*PPEB_LDR_DATA64*/ Ldr;
	RTL_USER_PROCESS_PARAMETERS* ProcessParameters;
} PEB64, * PPEB64;


typedef struct _PEB_LDR_DATA32 {
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
	ULONG EntryInProgress;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;

typedef struct _LDR_DATA_TABLE_ENTRY32 {
	LIST_ENTRY32 InLoadOrderLinks;
	LIST_ENTRY32 InMemoryOrderLinks;
	LIST_ENTRY32 InInitializationOrderLinks;
	ULONG DllBase;
	ULONG EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING32 FullDllName;
	UNICODE_STRING32 BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY32 HashLinks;
	ULONG SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	ULONG LoadedImports;
	ULONG EntryPointActivationContext;
	ULONG PatchInformation;
	LIST_ENTRY32 ForwarderLinks;
	LIST_ENTRY32 ServiceTagLinks;
	LIST_ENTRY32 StaticLinks;
	ULONG ContextInformation;
	ULONG OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY32, * PLDR_DATA_TABLE_ENTRY32;

typedef struct _PEB_LDR_DATA64 {
	ULONG Length;
	UCHAR Initialized;
	ULONG64 SsHandle;
	LIST_ENTRY64 InLoadOrderModuleList;
	LIST_ENTRY64 InMemoryOrderModuleList;
	LIST_ENTRY64 InInitializationOrderModuleList;
	ULONG64 EntryInProgress;
} PEB_LDR_DATA64, * PPEB_LDR_DATA64;

typedef struct _LDR_DATA_TABLE_ENTRY64 {
	LIST_ENTRY64 InLoadOrderLinks;
	LIST_ENTRY64 InMemoryOrderLinks;
	LIST_ENTRY64 InInitializationOrderLinks;
	ULONG64 DllBase;
	ULONG64 EntryPoint;
	ULONG64 SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY64 HashLinks;
	ULONG64 SectionPointer;
	ULONG64 CheckSum;
	ULONG64 TimeDateStamp;
	ULONG64 LoadedImports;
	ULONG64 EntryPointActivationContext;
	ULONG64 PatchInformation;
	LIST_ENTRY64 ForwarderLinks;
	LIST_ENTRY64 ServiceTagLinks;
	LIST_ENTRY64 StaticLinks;
	ULONG64 ContextInformation;
	ULONG64 OriginalBase;
	LARGE_INTEGER LoadTime;
} LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;

#define RVA(Instr, InstrSize) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + (InstrSize - sizeof(LONG))))
#define RVA2(Instr, InstrSize, Off) ((DWORD64)Instr + InstrSize + *(LONG*)((DWORD64)Instr + Off))

//typedef enum _PROCESS_INFORMATION_CLASS
//{
//	ProcessBasicInformation = 0, // 0, q: PROCESS_BASIC_INFORMATION, PROCESS_EXTENDED_BASIC_INFORMATION
//	ProcessQuotaLimits, // qs: QUOTA_LIMITS, QUOTA_LIMITS_EX
//	ProcessIoCounters, // q: IO_COUNTERS
//	ProcessVmCounters, // q: VM_COUNTERS, VM_COUNTERS_EX
//	ProcessTimes, // q: KERNEL_USER_TIMES
//	ProcessBasePriority, // s: KPRIORITY
//	ProcessRaisePriority, // s: ULONG
//	ProcessDebugPort, // q: HANDLE
//	ProcessExceptionPort, // s: HANDLE
//	ProcessAccessToken, // s: PROCESS_ACCESS_TOKEN
//	ProcessLdtInformation, // 10
//	ProcessLdtSize,
//	ProcessDefaultHardErrorMode, // qs: ULONG
//	ProcessIoPortHandlers, // (kernel-mode only)
//	ProcessPooledUsageAndLimits, // q: POOLED_USAGE_AND_LIMITS
//	ProcessWorkingSetWatch, // q: PROCESS_WS_WATCH_INFORMATION[]; s: void
//	ProcessUserModeIOPL,
//	ProcessEnableAlignmentFaultFixup, // s: BOOLEAN
//	ProcessPriorityClass, // qs: PROCESS_PRIORITY_CLASS
//	ProcessWx86Information,
//	ProcessHandleCount, // 20, q: ULONG, PROCESS_HANDLE_INFORMATION
//	ProcessAffinityMask, // s: KAFFINITY
//	ProcessPriorityBoost, // qs: ULONG
//	ProcessDeviceMap, // qs: PROCESS_DEVICEMAP_INFORMATION, PROCESS_DEVICEMAP_INFORMATION_EX
//	ProcessSessionInformation, // q: PROCESS_SESSION_INFORMATION
//	ProcessForegroundInformation, // s: PROCESS_FOREGROUND_BACKGROUND
//	ProcessWow64Information, // q: ULONG_PTR
//	ProcessImageFileName, // q: UNICODE_STRING
//	ProcessLUIDDeviceMapsEnabled, // q: ULONG
//	ProcessBreakOnTermination, // qs: ULONG
//	ProcessDebugObjectHandle, // 30, q: HANDLE
//	ProcessDebugFlags, // qs: ULONG
//	ProcessHandleTracing, // q: PROCESS_HANDLE_TRACING_QUERY; s: size 0 disables, otherwise enables
//	ProcessIoPriority, // qs: ULONG
//	ProcessExecuteFlags, // qs: ULONG
//	ProcessResourceManagement,
//	ProcessCookie, // q: ULONG
//	ProcessImageInformation, // q: SECTION_IMAGE_INFORMATION
//	ProcessCycleTime, // q: PROCESS_CYCLE_TIME_INFORMATION
//	ProcessPagePriority, // q: ULONG
//	ProcessInstrumentationCallback, // 40
//	ProcessThreadStackAllocation, // s: PROCESS_STACK_ALLOCATION_INFORMATION, PROCESS_STACK_ALLOCATION_INFORMATION_EX
//	ProcessWorkingSetWatchEx, // q: PROCESS_WS_WATCH_INFORMATION_EX[]
//	ProcessImageFileNameWin32, // q: UNICODE_STRING
//	ProcessImageFileMapping, // q: HANDLE (input)
//	ProcessAffinityUpdateMode, // qs: PROCESS_AFFINITY_UPDATE_MODE
//	ProcessMemoryAllocationMode, // qs: PROCESS_MEMORY_ALLOCATION_MODE
//	ProcessGroupInformation, // q: USHORT[]
//	ProcessTokenVirtualizationEnabled, // s: ULONG
//	ProcessConsoleHostProcess, // q: ULONG_PTR
//	ProcessWindowInformation, // 50, q: PROCESS_WINDOW_INFORMATION
//	ProcessHandleInformation, // q: PROCESS_HANDLE_SNAPSHOT_INFORMATION // since WIN8
//	ProcessMitigationPolicy, // s: PROCESS_MITIGATION_POLICY_INFORMATION
//	ProcessDynamicFunctionTableInformation,
//	ProcessHandleCheckingMode,
//	ProcessKeepAliveCount, // q: PROCESS_KEEPALIVE_COUNT_INFORMATION
//	ProcessRevokeFileHandles, // s: PROCESS_REVOKE_FILE_HANDLES_INFORMATION
//	MaxProcessInfoClass
//} PROCESS_INFORMATION_CLASS;

typedef struct _DBGKD_DEBUG_DATA_HEADER64 {
	//
	// Link to other blocks
	//
	LIST_ENTRY64 List;

	//
	// This is a unique tag to identify the owner of the block.
	// If your component only uses one pool tag, use it for this, too.
	//
	ULONG           OwnerTag;

	//
	// This must be initialized to the size of the data block,
	// including this structure.
	//
	ULONG           Size;

} DBGKD_DEBUG_DATA_HEADER64, * PDBGKD_DEBUG_DATA_HEADER64;

typedef struct _KDDEBUGGER_DATA64 {

	DBGKD_DEBUG_DATA_HEADER64 Header;

	//
	// Base address of kernel image
	//
	ULONG64   KernBase;

	//
	// DbgBreakPointWithStatus is a function which takes an argument
	// and hits a breakpoint.  This field contains the address of the
	// breakpoint instruction.  When the debugger sees a breakpoint
	// at this address, it may retrieve the argument from the first
	// argument register, or on x86 the eax register.
	//
	ULONG64   BreakpointWithStatus;       // address of breakpoint

	//
	// Address of the saved context record during a bugcheck
	//
	// N.B. This is an automatic in KeBugcheckEx's frame, and
	// is only valid after a bugcheck.
	//
	ULONG64   SavedContext;

	//
	// help for walking stacks with user callbacks:
	//

	//
	// The address of the thread structure is provided in the
	// WAIT_STATE_CHANGE packet.  This is the offset from the base of
	// the thread structure to the pointer to the kernel stack frame
	// for the currently active usermode callback.
	//
	USHORT  ThCallbackStack;            // offset in thread data

	//
	// these values are offsets into that frame:
	//
	USHORT  NextCallback;               // saved pointer to next callback frame
	USHORT  FramePointer;               // saved frame pointer

	//
	// pad to a quad boundary
	//
	USHORT  PaeEnabled;

	//
	// Address of the kernel callout routine.
	//
	ULONG64   KiCallUserMode;             // kernel routine

	//
	// Address of the usermode entry point for callbacks.
	//
	ULONG64   KeUserCallbackDispatcher;   // address in ntdll

	//
	// Addresses of various kernel data structures and lists
	// that are of interest to the kernel debugger.
	//

	ULONG64   PsLoadedModuleList;
	ULONG64   PsActiveProcessHead;
	ULONG64   PspCidTable;

	ULONG64   ExpSystemResourcesList;
	ULONG64   ExpPagedPoolDescriptor;
	ULONG64   ExpNumberOfPagedPools;

	ULONG64   KeTimeIncrement;
	ULONG64   KeBugCheckCallbackListHead;
	ULONG64   KiBugcheckData;

	ULONG64   IopErrorLogListHead;

	ULONG64   ObpRootDirectoryObject;
	ULONG64   ObpTypeObjectType;

	ULONG64   MmSystemCacheStart;
	ULONG64   MmSystemCacheEnd;
	ULONG64   MmSystemCacheWs;

	ULONG64   MmPfnDatabase;
	ULONG64   MmSystemPtesStart;
	ULONG64   MmSystemPtesEnd;
	ULONG64   MmSubsectionBase;
	ULONG64   MmNumberOfPagingFiles;

	ULONG64   MmLowestPhysicalPage;
	ULONG64   MmHighestPhysicalPage;
	ULONG64   MmNumberOfPhysicalPages;

	ULONG64   MmMaximumNonPagedPoolInBytes;
	ULONG64   MmNonPagedSystemStart;
	ULONG64   MmNonPagedPoolStart;
	ULONG64   MmNonPagedPoolEnd;

	ULONG64   MmPagedPoolStart;
	ULONG64   MmPagedPoolEnd;
	ULONG64   MmPagedPoolInformation;
	ULONG64   MmPageSize;

	ULONG64   MmSizeOfPagedPoolInBytes;

	ULONG64   MmTotalCommitLimit;
	ULONG64   MmTotalCommittedPages;
	ULONG64   MmSharedCommit;
	ULONG64   MmDriverCommit;
	ULONG64   MmProcessCommit;
	ULONG64   MmPagedPoolCommit;
	ULONG64   MmExtendedCommit;

	ULONG64   MmZeroedPageListHead;
	ULONG64   MmFreePageListHead;
	ULONG64   MmStandbyPageListHead;
	ULONG64   MmModifiedPageListHead;
	ULONG64   MmModifiedNoWritePageListHead;
	ULONG64   MmAvailablePages;
	ULONG64   MmResidentAvailablePages;

	ULONG64   PoolTrackTable;
	ULONG64   NonPagedPoolDescriptor;

	ULONG64   MmHighestUserAddress;
	ULONG64   MmSystemRangeStart;
	ULONG64   MmUserProbeAddress;

	ULONG64   KdPrintCircularBuffer;
	ULONG64   KdPrintCircularBufferEnd;
	ULONG64   KdPrintWritePointer;
	ULONG64   KdPrintRolloverCount;

	ULONG64   MmLoadedUserImageList;

	// NT 5.1 Addition

	ULONG64   NtBuildLab;
	ULONG64   KiNormalSystemCall;

	// NT 5.0 hotfix addition

	ULONG64   KiProcessorBlock;
	ULONG64   MmUnloadedDrivers;
	ULONG64   MmLastUnloadedDriver;
	ULONG64   MmTriageActionTaken;
	ULONG64   MmSpecialPoolTag;
	ULONG64   KernelVerifier;
	ULONG64   MmVerifierData;
	ULONG64   MmAllocatedNonPagedPool;
	ULONG64   MmPeakCommitment;
	ULONG64   MmTotalCommitLimitMaximum;
	ULONG64   CmNtCSDVersion;

	// NT 5.1 Addition

	ULONG64   MmPhysicalMemoryBlock;
	ULONG64   MmSessionBase;
	ULONG64   MmSessionSize;
	ULONG64   MmSystemParentTablePage;

	// Server 2003 addition

	ULONG64   MmVirtualTranslationBase;

	USHORT    OffsetKThreadNextProcessor;
	USHORT    OffsetKThreadTeb;
	USHORT    OffsetKThreadKernelStack;
	USHORT    OffsetKThreadInitialStack;

	USHORT    OffsetKThreadApcProcess;
	USHORT    OffsetKThreadState;
	USHORT    OffsetKThreadBStore;
	USHORT    OffsetKThreadBStoreLimit;

	USHORT    SizeEProcess;
	USHORT    OffsetEprocessPeb;
	USHORT    OffsetEprocessParentCID;
	USHORT    OffsetEprocessDirectoryTableBase;

	USHORT    SizePrcb;
	USHORT    OffsetPrcbDpcRoutine;
	USHORT    OffsetPrcbCurrentThread;
	USHORT    OffsetPrcbMhz;

	USHORT    OffsetPrcbCpuType;
	USHORT    OffsetPrcbVendorString;
	USHORT    OffsetPrcbProcStateContext;
	USHORT    OffsetPrcbNumber;

	USHORT    SizeEThread;

	ULONG64   KdPrintCircularBufferPtr;
	ULONG64   KdPrintBufferSize;

	ULONG64   KeLoaderBlock;

	USHORT    SizePcr;
	USHORT    OffsetPcrSelfPcr;
	USHORT    OffsetPcrCurrentPrcb;
	USHORT    OffsetPcrContainedPrcb;

	USHORT    OffsetPcrInitialBStore;
	USHORT    OffsetPcrBStoreLimit;
	USHORT    OffsetPcrInitialStack;
	USHORT    OffsetPcrStackLimit;

	USHORT    OffsetPrcbPcrPage;
	USHORT    OffsetPrcbProcStateSpecialReg;
	USHORT    GdtR0Code;
	USHORT    GdtR0Data;

	USHORT    GdtR0Pcr;
	USHORT    GdtR3Code;
	USHORT    GdtR3Data;
	USHORT    GdtR3Teb;

	USHORT    GdtLdt;
	USHORT    GdtTss;
	USHORT    Gdt64R3CmCode;
	USHORT    Gdt64R3CmTeb;

	ULONG64   IopNumTriageDumpDataBlocks;
	ULONG64   IopTriageDumpDataBlocks;

	// Longhorn addition

	ULONG64   VfCrashDataBlock;
	ULONG64   MmBadPagesDetected;
	ULONG64   MmZeroedPageSingleBitErrorsDetected;

	// Windows 7 addition

	ULONG64   EtwpDebuggerData;
	USHORT    OffsetPrcbContext;

	// Windows 8 addition

	USHORT    OffsetPrcbMaxBreakpoints;
	USHORT    OffsetPrcbMaxWatchpoints;

	ULONG     OffsetKThreadStackLimit;
	ULONG     OffsetKThreadStackBase;
	ULONG     OffsetKThreadQueueListEntry;
	ULONG     OffsetEThreadIrpList;

	USHORT    OffsetPrcbIdleThread;
	USHORT    OffsetPrcbNormalDpcState;
	USHORT    OffsetPrcbDpcStack;
	USHORT    OffsetPrcbIsrStack;

	USHORT    SizeKDPC_STACK_FRAME;

	// Windows 8.1 Addition

	USHORT    OffsetKPriQueueThreadListHead;
	USHORT    OffsetKThreadWaitReason;

	// Windows 10 RS1 Addition

	USHORT    Padding;
	ULONG64   PteBase;

	// Windows 10 RS5 Addition

	ULONG64 RetpolineStubFunctionTable;
	ULONG RetpolineStubFunctionTableSize;
	ULONG RetpolineStubOffset;
	ULONG RetpolineStubSize;

} KDDEBUGGER_DATA64, * PKDDEBUGGER_DATA64;

typedef struct _DUMP_HEADER
{
	ULONG Signature;
	ULONG ValidDump;
	ULONG MajorVersion;
	ULONG MinorVersion;
	ULONG_PTR DirectoryTableBase;
	ULONG_PTR PfnDataBase;
	PLIST_ENTRY PsLoadedModuleList;
	PLIST_ENTRY PsActiveProcessHead;
	ULONG MachineImageType;
	ULONG NumberProcessors;
	ULONG BugCheckCode;
	ULONG_PTR BugCheckParameter1;
	ULONG_PTR BugCheckParameter2;
	ULONG_PTR BugCheckParameter3;
	ULONG_PTR BugCheckParameter4;
	CHAR VersionUser[32];
	struct _KDDEBUGGER_DATA64* KdDebuggerDataBlock;
} DUMP_HEADER, * PDUMP_HEADER;

C_ASSERT(FIELD_OFFSET(DUMP_HEADER, Signature) == 0);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, ValidDump) == 4);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MajorVersion) == 8);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MinorVersion) == 0xc);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, DirectoryTableBase) == 0x10);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PfnDataBase) == 0x18);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsLoadedModuleList) == 0x20);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, PsActiveProcessHead) == 0x28);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, MachineImageType) == 0x30);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, NumberProcessors) == 0x34);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckCode) == 0x38);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter1) == 0x40);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter2) == 0x48);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter3) == 0x50);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, BugCheckParameter4) == 0x58);
C_ASSERT(FIELD_OFFSET(DUMP_HEADER, KdDebuggerDataBlock) == 0x80);

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation = 0x0,
	SystemProcessorInformation = 0x1,
	SystemPerformanceInformation = 0x2,
	SystemTimeOfDayInformation = 0x3,
	SystemPathInformation = 0x4,
	SystemProcessInformation = 0x5,
	SystemCallCountInformation = 0x6,
	SystemDeviceInformation = 0x7,
	SystemProcessorPerformanceInformation = 0x8,
	SystemFlagsInformation = 0x9,
	SystemCallTimeInformation = 0xa,
	SystemModuleInformation = 0xb,
	SystemLocksInformation = 0xc,
	SystemStackTraceInformation = 0xd,
	SystemPagedPoolInformation = 0xe,
	SystemNonPagedPoolInformation = 0xf,
	SystemHandleInformation = 0x10,
	SystemObjectInformation = 0x11,
	SystemPageFileInformation = 0x12,
	SystemVdmInstemulInformation = 0x13,
	SystemVdmBopInformation = 0x14,
	SystemFileCacheInformation = 0x15,
	SystemPoolTagInformation = 0x16,
	SystemInterruptInformation = 0x17,
	SystemDpcBehaviorInformation = 0x18,
	SystemFullMemoryInformation = 0x19,
	SystemLoadGdiDriverInformation = 0x1a,
	SystemUnloadGdiDriverInformation = 0x1b,
	SystemTimeAdjustmentInformation = 0x1c,
	SystemSummaryMemoryInformation = 0x1d,
	SystemMirrorMemoryInformation = 0x1e,
	SystemPerformanceTraceInformation = 0x1f,
	SystemObsolete0 = 0x20,
	SystemExceptionInformation = 0x21,
	SystemCrashDumpStateInformation = 0x22,
	SystemKernelDebuggerInformation = 0x23,
	SystemContextSwitchInformation = 0x24,
	SystemRegistryQuotaInformation = 0x25,
	SystemExtendServiceTableInformation = 0x26,
	SystemPrioritySeperation = 0x27,
	SystemVerifierAddDriverInformation = 0x28,
	SystemVerifierRemoveDriverInformation = 0x29,
	SystemProcessorIdleInformation = 0x2a,
	SystemLegacyDriverInformation = 0x2b,
	SystemCurrentTimeZoneInformation = 0x2c,
	SystemLookasideInformation = 0x2d,
	SystemTimeSlipNotification = 0x2e,
	SystemSessionCreate = 0x2f,
	SystemSessionDetach = 0x30,
	SystemSessionInformation = 0x31,
	SystemRangeStartInformation = 0x32,
	SystemVerifierInformation = 0x33,
	SystemVerifierThunkExtend = 0x34,
	SystemSessionProcessInformation = 0x35,
	SystemLoadGdiDriverInSystemSpace = 0x36,
	SystemNumaProcessorMap = 0x37,
	SystemPrefetcherInformation = 0x38,
	SystemExtendedProcessInformation = 0x39,
	SystemRecommendedSharedDataAlignment = 0x3a,
	SystemComPlusPackage = 0x3b,
	SystemNumaAvailableMemory = 0x3c,
	SystemProcessorPowerInformation = 0x3d,
	SystemEmulationBasicInformation = 0x3e,
	SystemEmulationProcessorInformation = 0x3f,
	SystemExtendedHandleInformation = 0x40,
	SystemLostDelayedWriteInformation = 0x41,
	SystemBigPoolInformation = 0x42,
	SystemSessionPoolTagInformation = 0x43,
	SystemSessionMappedViewInformation = 0x44,
	SystemHotpatchInformation = 0x45,
	SystemObjectSecurityMode = 0x46,
	SystemWatchdogTimerHandler = 0x47,
	SystemWatchdogTimerInformation = 0x48,
	SystemLogicalProcessorInformation = 0x49,
	SystemWow64SharedInformationObsolete = 0x4a,
	SystemRegisterFirmwareTableInformationHandler = 0x4b,
	SystemFirmwareTableInformation = 0x4c,
	SystemModuleInformationEx = 0x4d,
	SystemVerifierTriageInformation = 0x4e,
	SystemSuperfetchInformation = 0x4f,
	SystemMemoryListInformation = 0x50,
	SystemFileCacheInformationEx = 0x51,
	SystemThreadPriorityClientIdInformation = 0x52,
	SystemProcessorIdleCycleTimeInformation = 0x53,
	SystemVerifierCancellationInformation = 0x54,
	SystemProcessorPowerInformationEx = 0x55,
	SystemRefTraceInformation = 0x56,
	SystemSpecialPoolInformation = 0x57,
	SystemProcessIdInformation = 0x58,
	SystemErrorPortInformation = 0x59,
	SystemBootEnvironmentInformation = 0x5a,
	SystemHypervisorInformation = 0x5b,
	SystemVerifierInformationEx = 0x5c,
	SystemTimeZoneInformation = 0x5d,
	SystemImageFileExecutionOptionsInformation = 0x5e,
	SystemCoverageInformation = 0x5f,
	SystemPrefetchPatchInformation = 0x60,
	SystemVerifierFaultsInformation = 0x61,
	SystemSystemPartitionInformation = 0x62,
	SystemSystemDiskInformation = 0x63,
	SystemProcessorPerformanceDistribution = 0x64,
	SystemNumaProximityNodeInformation = 0x65,
	SystemDynamicTimeZoneInformation = 0x66,
	SystemCodeIntegrityInformation = 0x67,
	SystemProcessorMicrocodeUpdateInformation = 0x68,
	SystemProcessorBrandString = 0x69,
	SystemVirtualAddressInformation = 0x6a,
	SystemLogicalProcessorAndGroupInformation = 0x6b,
	SystemProcessorCycleTimeInformation = 0x6c,
	SystemStoreInformation = 0x6d,
	SystemRegistryAppendString = 0x6e,
	SystemAitSamplingValue = 0x6f,
	SystemVhdBootInformation = 0x70,
	SystemCpuQuotaInformation = 0x71,
	SystemNativeBasicInformation = 0x72,
	SystemErrorPortTimeouts = 0x73,
	SystemLowPriorityIoInformation = 0x74,
	SystemBootEntropyInformation = 0x75,
	SystemVerifierCountersInformation = 0x76,
	SystemPagedPoolInformationEx = 0x77,
	SystemSystemPtesInformationEx = 0x78,
	SystemNodeDistanceInformation = 0x79,
	SystemAcpiAuditInformation = 0x7a,
	SystemBasicPerformanceInformation = 0x7b,
	SystemQueryPerformanceCounterInformation = 0x7c,
	SystemSessionBigPoolInformation = 0x7d,
	SystemBootGraphicsInformation = 0x7e,
	SystemScrubPhysicalMemoryInformation = 0x7f,
	SystemBadPageInformation = 0x80,
	SystemProcessorProfileControlArea = 0x81,
	SystemCombinePhysicalMemoryInformation = 0x82,
	SystemEntropyInterruptTimingInformation = 0x83,
	SystemConsoleInformation = 0x84,
	SystemPlatformBinaryInformation = 0x85,
	SystemThrottleNotificationInformation = 0x86,
	SystemHypervisorProcessorCountInformation = 0x87,
	SystemDeviceDataInformation = 0x88,
	SystemDeviceDataEnumerationInformation = 0x89,
	SystemMemoryTopologyInformation = 0x8a,
	SystemMemoryChannelInformation = 0x8b,
	SystemBootLogoInformation = 0x8c,
	SystemProcessorPerformanceInformationEx = 0x8d,
	SystemSpare0 = 0x8e,
	SystemSecureBootPolicyInformation = 0x8f,
	SystemPageFileInformationEx = 0x90,
	SystemSecureBootInformation = 0x91,
	SystemEntropyInterruptTimingRawInformation = 0x92,
	SystemPortableWorkspaceEfiLauncherInformation = 0x93,
	SystemFullProcessInformation = 0x94,
	SystemKernelDebuggerInformationEx = 0x95,
	SystemBootMetadataInformation = 0x96,
	SystemSoftRebootInformation = 0x97,
	SystemElamCertificateInformation = 0x98,
	SystemOfflineDumpConfigInformation = 0x99,
	SystemProcessorFeaturesInformation = 0x9a,
	SystemRegistryReconciliationInformation = 0x9b,
	MaxSystemInfoClass = 0x9c,
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY {
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION
{
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER CreateTime;
	ULONG WaitTime;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG ContextSwitches;
	ULONG ThreadState;
	KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;
typedef struct _SYSTEM_PROCESS_INFO
{
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	LARGE_INTEGER WorkingSetPrivateSize;
	ULONG HardFaultCount;
	ULONG NumberOfThreadsHighWatermark;
	ULONGLONG CycleTime;
	LARGE_INTEGER CreateTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER KernelTime;
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	HANDLE InheritedFromUniqueProcessId;
	ULONG HandleCount;
	ULONG SessionId;
	ULONG_PTR UniqueProcessKey;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG PageFaultCount;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	SIZE_T QuotaPeakPagedPoolUsage;
	SIZE_T QuotaPagedPoolUsage;
	SIZE_T QuotaPeakNonPagedPoolUsage;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	SYSTEM_THREAD_INFORMATION Threads[1];
}SYSTEM_PROCESS_INFO, * PSYSTEM_PROCESS_INFO;

typedef struct _SYSTEM_SESSION_PROCESS_INFORMATION
{
	ULONG SessionId;
	ULONG SizeOfBuf;
	PVOID Buffer;
}SYSTEM_SESSION_PROCESS_INFORMATION, * PSYSTEM_SESSION_PROCESS_INFORMATION;

typedef struct _OBJECT_TYPE_INFORMATION
{
	UNICODE_STRING TypeName;
	ULONG TotalNumberOfObjects;
	ULONG TotalNumberOfHandles;
	ULONG Reserved[40];
} OBJECT_TYPE_INFORMATION, * POBJECT_TYPE_INFORMATION;

typedef struct _SYSTEM_SERVICE_TABLE {
	LONG* ServiceTable;
	PVOID ServiceCounterTableBase;
	ULONG64 NumberOfService;
	PVOID ParamTableBase;
}_SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO
{
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION
{
	ULONG NumberOfHandles;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
}SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX
{
	PVOID Object;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR HandleValue;
	ULONG GrantedAccess;
	USHORT CreatorBackTraceIndex;
	USHORT ObjectTypeIndex;
	ULONG HandleAttributes;
	ULONG Reserved;
}SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO_EX;

typedef struct _SYSTEM_HANDLE_INFORMATION_EX
{
	ULONG_PTR NumberOfHandles;
	ULONG_PTR Reserved;
	SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX Handles[1];
}SYSTEM_HANDLE_INFORMATION_EX, * PSYSTEM_HANDLE_INFORMATION_EX;

typedef struct _CFG_CALL_TARGET_INFO {
	ULONG_PTR Offset;
	ULONG_PTR Flags;
} CFG_CALL_TARGET_INFO, * PCFG_CALL_TARGET_INFO;

typedef struct _VM_INFORMATION
{
	DWORD NumberOfOffsets;
	DWORD MustBeZero;
	PVOID TargetsProcessed;
	PCFG_CALL_TARGET_INFO CallTargets;
	union _Section
	{
		HANDLE Section;
		DWORD64 Data;
	} Section;
	ULONG64 ExpectedFileOffset;
} VM_INFORMATION, * PVM_INFORMATION;

union MiscFlags
{
	struct
	{
		ULONG AutoBoostActive : 1;                                        //0x74
		ULONG ReadyTransition : 1;                                        //0x74
		ULONG WaitNext : 1;                                               //0x74
		ULONG SystemAffinityActive : 1;                                   //0x74
		ULONG Alertable : 1;                                              //0x74
		ULONG UserStackWalkActive : 1;                                    //0x74
		ULONG ApcInterruptRequest : 1;                                    //0x74
		ULONG QuantumEndMigrate : 1;                                      //0x74
		ULONG UmsDirectedSwitchEnable : 1;                                //0x74
		ULONG TimerActive : 1;                                            //0x74
		ULONG SystemThread : 1;                                           //0x74
		ULONG ProcessDetachActive : 1;                                    //0x74
		ULONG CalloutActive : 1;                                          //0x74
		ULONG ScbReadyQueue : 1;                                          //0x74
		ULONG ApcQueueable : 1;                                           //0x74
		ULONG ReservedStackInUse : 1;                                     //0x74
		ULONG UmsPerformingSyscall : 1;                                   //0x74
		ULONG TimerSuspended : 1;                                         //0x74
		ULONG SuspendedWaitMode : 1;                                      //0x74
		ULONG SuspendSchedulerApcWait : 1;                                //0x74
		ULONG CetUserShadowStack : 1;                                     //0x74
		ULONG BypassProcessFreeze : 1;                                    //0x74
		ULONG Reserved : 10;                                              //0x74
	};
	LONG AsLong;                                                     //0x74
};

typedef struct _KNONVOLATILE_CONTEXT_POINTERS {
	union {
		PM128A FloatingContext[16];
		struct {
			PM128A Xmm0;
			PM128A Xmm1;
			PM128A Xmm2;
			PM128A Xmm3;
			PM128A Xmm4;
			PM128A Xmm5;
			PM128A Xmm6;
			PM128A Xmm7;
			PM128A Xmm8;
			PM128A Xmm9;
			PM128A Xmm10;
			PM128A Xmm11;
			PM128A Xmm12;
			PM128A Xmm13;
			PM128A Xmm14;
			PM128A Xmm15;
		};
	};

	union {
		PULONG64 IntegerContext[16];
		struct {
			PULONG64 Rax;
			PULONG64 Rcx;
			PULONG64 Rdx;
			PULONG64 Rbx;
			PULONG64 Rsp;
			PULONG64 Rbp;
			PULONG64 Rsi;
			PULONG64 Rdi;
			PULONG64 R8;
			PULONG64 R9;
			PULONG64 R10;
			PULONG64 R11;
			PULONG64 R12;
			PULONG64 R13;
			PULONG64 R14;
			PULONG64 R15;
		};
	};

} KNONVOLATILE_CONTEXT_POINTERS, * PKNONVOLATILE_CONTEXT_POINTERS;

typedef struct _IMAGE_RUNTIME_FUNCTION_ENTRY RUNTIME_FUNCTION, * PRUNTIME_FUNCTION;

typedef struct _KSTACK_CONTROL
{
	ULONGLONG StackBase;                                                    //0x0
	union
	{
		ULONGLONG ActualLimit;                                              //0x8
		ULONGLONG StackExpansion : 1;                                         //0x8
	};
	struct
	{
		ULONGLONG StackBase;                                                    //0x10
		ULONGLONG StackLimit;                                                   //0x18
		ULONGLONG KernelStack;                                                  //0x20
		ULONGLONG InitialStack;                                                 //0x28
		ULONGLONG KernelShadowStackBase;                                        //0x30
		ULONGLONG KernelShadowStackLimit;										//0x38
		ULONGLONG KernelShadowStack;                                            //0x40
		ULONGLONG KernelShadowStackInitial;                                     //0x48
	} Previous;
}KERNEL_STACK_CONTROL, KSTACK_CONTROL, * PKERNEL_STACK_CONTROL, * PKSTACK_CONTROL;
static_assert(sizeof(KERNEL_STACK_CONTROL) == 0x50, "size mismatch");


//Physical or Virtual is Ok
//just assume it's not large page
#define IsAcrossPages(Address,size) (( PAGE_ALIGN((u64)Address+(u64)size) == PAGE_ALIGN(Address) ) ? FALSE : TRUE)

#define noinl __declspec(noinline)
#define naked __declspec(naked)
#define inl __forceinline
#define ConstStrLen(Str) ((sizeof(Str) - sizeof(Str[0])) / sizeof(Str[0]))
#define ToLower(Char) ((Char >= 'A' && Char <= 'Z') ? (Char + 32) : Char)
#define ToUpper(Char) ((Char >= 'a' && Char <= 'z') ? (Char - 'a') : Char)
#define NT_HEADER(Base) (PIMAGE_NT_HEADERS)((ULONG64)(Base) + ((PIMAGE_DOS_HEADER)(Base))->e_lfanew)
