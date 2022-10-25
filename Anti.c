#include"Anti.h"
NTSTATUS passHandleDown(DWORD32 dwPid, DWORD32 dwTargetPid) {

	PEPROCESS pEProcess;
	PsLookupProcessByProcessId(dwPid, &pEProcess);
	ULONG64 eprocess = pEProcess;
	PULONG64 pObjectTable = eprocess + 0x570;
	ULONG64 TableCode = *pObjectTable + 0x8;
	PULONG64 TableAddr = TableCode & (~0x7);
	ULONG64 flag = TableCode & 0x7;
	if (flag!=0) {
		DbgPrint("多级目录,未处理\n");
		return 0;
	}

}