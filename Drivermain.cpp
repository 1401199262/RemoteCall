#include "global.h"
#include "SetContextUserCall.h"


PVOID NtBase = 0;
PDRIVER_OBJECT g_DriverObject = 0;
int _fltused = 0;

VOID DriverUnload(DRIVER_OBJECT* DriverObject)
{

}


NTSTATUS DriverEntry(PDRIVER_OBJECT DrvObj, PVOID reg)
{
	//DrvObj->DriverUnload = DriverUnload;

	g_DriverObject = DrvObj;
	getKernelModuleByName("ntoskrnl.exe", &::NtBase);

	__dbgdb();
	CtxCall.Call();

	return 0;
}


