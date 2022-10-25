#include "processUtil.h"
#include "ModuleUtil.h"
char* g_ImageName = 0;
NTSTATUS QueryProcessMemory(DWORD32 PID,PVOID64 BaseAddress, PMYMEMORY_BASIC_INFORMATION pmyMemInfo,ULONG64 bufferSize)
{

	//���̹ҿ�	
	PEPROCESS eprocess;
	PsLookupProcessByProcessId(PID, &eprocess);
	KAPC_STATE apcState = {0};
	__try
	{
		ProbeForRead(pmyMemInfo, bufferSize,4);
	}
	__except (1)
	{
		DbgPrint("3����ַ����\n");
		return R3ADDRESSERROR;
	}
	//��ȡ�ڴ���Ϣ
	NTSTATUS state;
	ULONG64 proint_test	= ExAllocatePool(NonPagedPool,sizeof(MEMORY_BASIC_INFORMATION));
	PMEMORY_BASIC_INFORMATION memInfo = proint_test;
	MEMORY_INFORMATION_CLASS memclass;
	KeStackAttachProcess(eprocess, &apcState);
	if (!MmIsAddressValid(proint_test)) {
		return MALLOCERROR;
	}
	state = ZwQueryVirtualMemory(ZwCurrentProcess(), BaseAddress, MemoryBasicInformation, memInfo, sizeof(MEMORY_BASIC_INFORMATION), NULL);
	if (!NT_SUCCESS(state)) {
		DbgPrint("��ѯ�ڴ���Ϣ����");
		KeUnstackDetachProcess(&apcState);
		ExFreePool(memInfo);
		return state;
	}
	//�����ҿ�
	KeUnstackDetachProcess(&apcState);
	pmyMemInfo->BaseAddress= memInfo->BaseAddress;
	pmyMemInfo->AllocationBase= memInfo->AllocationBase;
	pmyMemInfo->AllocationProtect= memInfo->AllocationProtect;
	pmyMemInfo->RegionSize= memInfo->RegionSize;
	pmyMemInfo->State= memInfo->State;
	pmyMemInfo->Protect= memInfo->Protect;
	pmyMemInfo->Type= memInfo->Type;
	if (MmIsAddressValid(proint_test)) {
		ExFreePool(proint_test);
	}

	return state;
}
PVOID64 g_pathAddr = NULL;
unsigned char g_origHex[6] = { 0 };
DWORD32 g_pid = 0;
//path�ص�ǩ����֤
NTSTATUS pathCallBack(ULONG64* mdlAddr, ULONG64* pMdl) {

	unsigned char MmVerifyCallbackFunctionCheckFlags[] =
	{
	  0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x6C, 0x24, 0x10,
	  0x48, 0x89, 0x74, 0x24, 0x18, 0x57, 0x48, 0x83, 0xEC, 0x20,
	  0x8B, 0xFA, 0x48, 0x8B, 0xF1, 0xE8, 0xcc, 0xcc, 0xcc, 0xcc,
	  0x83, 0xF8, 0x01, 0x74, 0xcc, 0x65, 0x48, 0x8B, 0x2C, 0x25,
	  0x88, 0x01, 0x00, 0x00, 0x33, 0xDB, 0x66, 0xFF, 0x8D, 0xE4,
	  0x01, 0x00, 0x00, 0xB2, 0x01, 0x48, 0x8D, 0xcc, 0xcc, 0xcc,
	  0xcc, 0x00, 0xE8, 0xcc, 0xcc, 0xcc, 0xcc, 0x33, 0xD2, 0x48,
	  0x8B, 0xCE, 0xE8, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x85, 0xC0,
	  0x74, 0xcc, 0x85, 0xFF, 0x74, 0xcc, 0x8B, 0x40, 0x68, 0x85,
	  0xC7, 0x74, 0xcc
	};
	unsigned char PathArr[] = {
	0xB8,0x01,0x00,0x00,0x00,0xc3
	};
	CHAR moduleName[] = "ntoskrnl.exe";
	CHAR sectionName[] = ".text";
	g_pathAddr =  SearchCode(moduleName, sectionName, MmVerifyCallbackFunctionCheckFlags, sizeof(MmVerifyCallbackFunctionCheckFlags));
	if (!MmIsAddressValid(g_pathAddr)) {
		DbgPrint("Patchʧ�ܣ���ַδ�ҵ����ַ��Ч\n");
		return -1 ;
	}
	memcpy(g_origHex, g_pathAddr, 6);
	*pMdl =IoAllocateMdl(g_pathAddr, 6, FALSE, FALSE, NULL);
	if (*pMdl == NULL)return -1;
	//�����ڴ�ҳ
	__try {
		MmProbeAndLockPages(*pMdl, KernelMode, IoWriteAccess);
	}
	__except (1) {
		DbgPrint("MDl�ڴ�����ʧ��\n");
		IoFreeMdl(*pMdl);
		return -1;
	}
	*mdlAddr = MmMapLockedPagesSpecifyCache(*pMdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (*mdlAddr == NULL)return -1;
	memcpy(*mdlAddr, PathArr, 6);
	DbgPrint("MmVerifyCallbackFunctionCheckFlags Patch Sucess Addr:%p\n", g_pathAddr);
	return STATUS_SUCCESS;
}
void unPathCallBack(PVOID64 mdlAddr, PMDL pMdl) {

	if (mdlAddr !=NULL) {
		if (g_origHex[0] != 0) {
			memcpy(mdlAddr, g_origHex, 6);
			MmUnmapLockedPages(mdlAddr, pMdl);
			MmUnlockPages(pMdl);
			IoFreeMdl(pMdl);
			DbgPrint("MmVerifyCallbackFunctionCheckFlags Patch Close Addr:%p\n", g_pathAddr);
		}
	}
}
//����jmpEcx
PVOID64 SearchJmpEcx() {
	CHAR moduleName[] = "ntoskrnl.exe";
	UCHAR tzm[] = { 0xff,0xe1 };
	PVOID64 codeAddr = SearchCode(moduleName, NULL, tzm, sizeof(tzm));
	return codeAddr;
}
//�ص�����
OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	DWORD32 pid = g_pid;
	PEPROCESS pEprocess;
	PsLookupProcessByProcessId(pid, &pEprocess);
	if (OperationInformation->Object== pEprocess) {
		
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = 0;
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = 0;
		DbgPrint("�ѽ�Ȩ DesiredAccess:%d\n", OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
	}
	return OB_PREOP_SUCCESS;
}
//ȥ�ص�����
OB_PREOP_CALLBACK_STATUS PathPobPreOperationCallbacktest(
	PVOID RegistrationContext,
	POB_PRE_OPERATION_INFORMATION OperationInformation
)
{
	DWORD32 pid = g_pid;
	PEPROCESS pEprocess;
	PsLookupProcessByProcessId(pid, &pEprocess);
	if (OperationInformation->Object == pEprocess) {
		
		OperationInformation->Parameters->CreateHandleInformation.DesiredAccess = OperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess;
		OperationInformation->Parameters->DuplicateHandleInformation.DesiredAccess = OperationInformation->Parameters->DuplicateHandleInformation.OriginalDesiredAccess;
		DbgPrint("�ص�����Ȩ DesiredAccess:%d\n ", OperationInformation->Parameters->CreateHandleInformation.DesiredAccess);
	}
	return OB_PREOP_SUCCESS;
}
HANDLE Hregister = NULL;
HANDLE PathHregister = NULL;
//�����ص�����
NTSTATUS ProtectProcess(DWORD32 PID)
{
	NTSTATUS state;
	OB_CALLBACK_REGISTRATION callBackRegis;
	OB_OPERATION_REGISTRATION operation;
	//����jmp ecx
	PVOID64 jmpEcxAddr = SearchJmpEcx();
	if (!MmIsAddressValid(jmpEcxAddr)) {
		return	-1;
	}
	g_pid = PID;
	callBackRegis.Version = OB_FLT_REGISTRATION_VERSION;
	callBackRegis.OperationRegistrationCount = 1;
	UNICODE_STRING altitude =  RTL_CONSTANT_STRING(L"9999");
	callBackRegis.Altitude = altitude;
	callBackRegis.RegistrationContext = PobPreOperationCallback; //����x64 rcx����,��ת��Ŀ��ص�����
	callBackRegis.OperationRegistration = &operation;
	operation.ObjectType = PsProcessType;
	operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operation.PreOperation = jmpEcxAddr;
	operation.PostOperation = NULL;
	//�رջص�ǩ����֤
	ULONG64 mdlAddr = 0;
	ULONG64 pMdl = 0;
	pathCallBack(&mdlAddr,&pMdl);
	state = ObRegisterCallbacks(&callBackRegis, &Hregister);
	if (!NT_SUCCESS(state)) {
		DbgPrint("�ص�����ʧ�� ErrorCocde:%x", state);
	}
	//�ָ��ص�ǩ����֤
	unPathCallBack(mdlAddr, pMdl);
	return 0;
}
//ժ���ص�����
NTSTATUS UnProtectProcess() {
	if (Hregister!=NULL) {
		ObUnRegisterCallbacks(Hregister);
	}
	return 0;
}
//����ȥ�ص�����
NTSTATUS PathProtectProcess(DWORD32 PID)
{
	NTSTATUS state;
	OB_CALLBACK_REGISTRATION callBackRegis;
	OB_OPERATION_REGISTRATION operation;
	//����jmp ecx
	PVOID64 jmpEcxAddr = SearchJmpEcx();
	if (!MmIsAddressValid(jmpEcxAddr)) {
		return	-1;
	}
	g_pid = PID;
	callBackRegis.Version = OB_FLT_REGISTRATION_VERSION;
	callBackRegis.OperationRegistrationCount = 1;
	UNICODE_STRING altitude = RTL_CONSTANT_STRING(L"1");
	callBackRegis.Altitude = altitude;
	callBackRegis.RegistrationContext = PathPobPreOperationCallbacktest;
	callBackRegis.OperationRegistration = &operation;
	operation.ObjectType = PsProcessType;
	operation.Operations = OB_OPERATION_HANDLE_CREATE | OB_OPERATION_HANDLE_DUPLICATE;
	operation.PreOperation = jmpEcxAddr;
	operation.PostOperation = NULL;
	//�رջص�ǩ����֤
	ULONG64 mdlAddr = 0;
	ULONG64 pMdl = 0;
	pathCallBack(&mdlAddr, &pMdl);
	state = ObRegisterCallbacks(&callBackRegis, &PathHregister);
	if (!NT_SUCCESS(state)) {
		DbgPrint("�ص�����ʧ�� ErrorCocde:%x", state);
	}
	//�ָ��ص�ǩ����֤
	unPathCallBack(mdlAddr, pMdl);
	return 0;
}
//ժ��ȥ�ص�����
NTSTATUS UnPathProtectProcess() {
	if (PathHregister != NULL) {
		ObUnRegisterCallbacks(PathHregister);
	}
	return 0;
}

void PcreateProcessNotifyRoutineEx(
	PEPROCESS Process,
	HANDLE ProcessId,
	PPS_CREATE_NOTIFY_INFO CreateInfo
)
{
	ANSI_STRING ansiString;
	NTSTATUS ntstatus;
	RtlInitAnsiString(&ansiString, g_ImageName);
	UNICODE_STRING64 imageName;
	ntstatus = RtlAnsiStringToUnicodeString(&imageName, &ansiString, TRUE);
	if (!NT_SUCCESS(ntstatus))return;
	if (CreateInfo == NULL) {
		//DbgPrint("��������\n");
		return;
	}
	if (CreateInfo->ImageFileName == NULL) return;
	DbgPrint("����·��:%ws\n", CreateInfo->ImageFileName->Buffer);
	DbgPrint("����·��:%ws\n", imageName.Buffer);
	if (wcsstr(CreateInfo->ImageFileName->Buffer, imageName.Buffer) != NULL) {
		CreateInfo->CreationStatus = STATUS_ACCESS_VIOLATION;
	}
	RtlFreeUnicodeString(&imageName);
}
NTSTATUS StopCreateProcess(char* imageName) {
	NTSTATUS ntstatus;
	g_ImageName =  ExAllocatePool(NonPagedPool, strlen(imageName)+1);
	if (g_ImageName == NULL) {
		return -1;
	}
	memcpy(g_ImageName, imageName, strlen(imageName) + 1);
	ntstatus = PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx,FALSE);
	return ntstatus;
}
void UnStopCreateProcess() {
	PsSetCreateProcessNotifyRoutineEx(PcreateProcessNotifyRoutineEx, TRUE);
	if (g_ImageName != NULL) {
		ExFreePool(g_ImageName);
	}
	
}
