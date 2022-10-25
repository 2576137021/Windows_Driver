#include"ThreadUtil.h"
#include"ErrorCode.h"
#include"ModuleUtil.h"
#include"windowsApi.h"
#include"MmRw.h"
NTSTATUS SuspendThread(DWORD32 dwThreadId)
{
	PETHREAD pEthread;
	NTSTATUS state;
	state = PsLookupThreadByThreadId(dwThreadId, &pEthread);
	if (!NT_SUCCESS(state)) {
		
		return GET_ETHREAD_ERROR;
	}
	unsigned char PsSuspendThreadcode[] =
	{
	  0x48, 0x89, 0x54, 0x24, 0xcc, 0x48, 0x89, 0x4C, 0x24, 0xcc,
	  0x53, 0x56, 0x57, 0x41, 0x56, 0x41, 0x57, 0x48, 0x83, 0xEC,
	  0xcc, 0x4C, 0x8B, 0xF2, 0x48, 0x8B, 0xF9, 0x83, 0x64, 0x24,
	  0xcc, 0xcc, 0x65, 0x48, 0x8B, 0x34, 0x25, 0xcc, 0xcc, 0xcc,
	  0xcc, 0x48, 0x89, 0x74, 0x24, 0xcc, 0x66, 0xFF, 0x8E, 0xcc,
	  0xcc, 0xcc, 0xcc, 0x4C, 0x8D, 0xB9, 0xcc, 0xcc, 0xcc, 0xcc,
	  0x4C, 0x89, 0x7C, 0x24, 0xcc, 0x49, 0x8B, 0xCF, 0xE8, 0xcc,
	  0xcc, 0xcc, 0xFF, 0x84, 0xC0, 0x0F, 0x84, 0xcc, 0xcc, 0xcc,
	  0xcc, 0x8B, 0x87, 0xcc, 0xcc, 0xcc, 0xcc, 0xA8, 0x01, 0x0F,
	  0x85, 0xcc, 0xcc, 0xcc, 0xcc
	};
	char moduleName[] = "ntoskrnl.exe";
	char sectionName[] = "PAGE";
	PVOID funAddr = SearchCode(moduleName, sectionName, PsSuspendThreadcode, sizeof(PsSuspendThreadcode));
	if (!MmIsAddressValid(funAddr)) {

		return SEARCH_FUNCTION_ADDRESS_ERROR;
	}
	PsSuspendThread testSuspendThread = funAddr;
	ULONG PreviousSuspendCount;
	state = testSuspendThread(pEthread, &PreviousSuspendCount);
	if (!NT_SUCCESS(state)) {

		return SUSPENDTHREAD_ERROR;
	}
	return state;
}
NTSTATUS ResumeThread(DWORD32 dwThreadId)
{
	PETHREAD pEthread;
	NTSTATUS state;
	state = PsLookupThreadByThreadId(dwThreadId, &pEthread);
	if (!NT_SUCCESS(state)) {

		return GET_ETHREAD_ERROR;
	}
	unsigned char tzcode[] =
	{
	  0x48, 0x89, 0x5C, 0x24, 0xcc, 0x48, 0x89, 0x74, 0x24, 0xcc,
	  0x57, 0x48, 0x83, 0xEC, 0xcc, 0x48, 0x8B, 0xDA, 0x48, 0x8B,
	  0xF9, 0xE8, 0xcc, 0xcc, 0xcc, 0xcc, 0x65, 0x48, 0x8B, 0x14,
	  0x25, 0x88, 0x01, 0x00, 0x00, 0x8B, 0xF0, 0x83, 0xF8, 0x01,
	  0x75, 0xcc, 0x4C, 0x8B, 0x87, 0xcc, 0xcc, 0xcc, 0xcc, 0xB8,
	  0x00, 0x80, 0x00, 0x00, 0x41, 0x8B, 0x88, 0xcc, 0xcc, 0xcc,
	  0xcc, 0x85, 0xC8, 0x74, 0xcc, 0x0F, 0xBA, 0xE1, 0xcc, 0x0F,
	  0x82, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x85, 0xDB
	};
	char moduleName[] = "ntoskrnl.exe";
	char sectionName[] = "PAGE";
	PVOID funAddr = SearchCode(moduleName, sectionName, tzcode, sizeof(tzcode));
	if (!MmIsAddressValid(funAddr)) {

		return SEARCH_FUNCTION_ADDRESS_ERROR;
	}
	ULONG count = 0;
	PsResumeThread testResumeThread = funAddr;
	state = testResumeThread(pEthread,&count);
	return state;
}
/*
dwStartAddr32 地址必须存在于目标进程内
且具有以下格式
void _declspec(naked) pushAll() {
	_asm {
		//这一条是留空指令,等待驱动填充
		call $ + 5;
		pushad;
		call injectCode;
		popad;
		ret;
	}
}
*/
NTSTATUS ThreadHijackInject(DWORD32 dwThreadId, DWORD32 dwStartAddr32) {

	PETHREAD pEthread;
	NTSTATUS state;
	char pushEIP[5] = { 0x68,0,0,0,0 };
	state = SuspendThread(dwThreadId);
	if (!NT_SUCCESS(state)) {

		return -1;
	}
	state = PsLookupThreadByThreadId(dwThreadId, &pEthread);
	if (!NT_SUCCESS(state)) {

		return GET_ETHREAD_ERROR;
	}
	ULONG64 pTemp = pEthread;
	pTemp+=0xf0;
	
	if (!MmIsAddressValid(pTemp)) {
		return POINT_ERROR;
	}
	pTemp = *(ULONG64*)pTemp;
	//teb是3环地址,进程挂靠
	ULONG64 processTemp = (ULONG64)pEthread + 0x478;
	DWORD64 pid = *(ULONG64*)processTemp;
	PEPROCESS pEprocess;
	state = PsLookupProcessByProcessId(pid, &pEprocess);
	if (!NT_SUCCESS(state)) {
		return -1;
	}
	KAPC_STATE apcSate = { 0 };
	KeStackAttachProcess(pEprocess, &apcSate);
	DbgPrint("Teb:%p\n", pTemp);
	pTemp += 0x1488;
	if (!MmIsAddressValid(pTemp)) {
		return POINT_ERROR;
	}
	pTemp = *(DWORD32*)pTemp;
	pTemp += 0x4;
	DWORD32 pContext = pTemp;
	//保存context
	//SaveContext(pContext, 0, dwThreadId);
	if (!MmIsAddressValid(pContext)) {
		return POINT_ERROR;
	}
	//eip
	pContext += 0xb8;
	if (!MmIsAddressValid(pContext)){
		return POINT_ERROR; 
	}
	//在目标程序保存eip
	DbgPrint("当前eip:%p\n", *(DWORD32*)pContext);
	memcpy(&pushEIP[1], pContext, 4);
	PMDL g_pMDL = MmCreateMdl(NULL, dwStartAddr32,10);
	if (g_pMDL == NULL)
	{
		return -1;
	}
	MmBuildMdlForNonPagedPool(g_pMDL);  //建立内存页的MDL描述
	g_pMDL->MdlFlags |= MDL_MAPPED_TO_SYSTEM_VA;   //改变MDL的标记为可写
	PVOID64 pMdlAddr = MmMapLockedPages(g_pMDL, KernelMode);    //映射MDL空间
	memcpy(pMdlAddr, pushEIP, 5);
	//MmUnmapLockedPages(newAddress, pPMDL);
	//修改eip
	*(DWORD32*)pContext = dwStartAddr32;
	//取消映射
	MmUnmapLockedPages(pMdlAddr, g_pMDL);
	IoFreeMdl(g_pMDL);
	//解除挂靠
	KeUnstackDetachProcess(&apcSate);
	//恢复线程
	state = ResumeThread(dwThreadId);
	return state;
}


