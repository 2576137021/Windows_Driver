#include"uitlFun_Win7.h"
#include"ThreadUtil.h"
MyExpDisQueryAttributeInformation oldQueryFun = NULL;
MyExpDisQueryAttributeInformation oldSetFun = NULL;
_ExRegisterAttributeInformationCallback regCallBack = NULL;
PULONG64 AttributeInformation = 0;
NTSTATUS status = 0;
//������תվ
NTSTATUS DispatchCallEntry(PMESSAGE_PACKAGE packge) {
	DbgPrint("�ѽ��յ���������\n");
	if (packge->funNum==1) {
		PMmpack mmpack = packge->data;
		status = ReadR3Memory(mmpack->pid, mmpack->buffer, mmpack->readAddr, mmpack->size);
		
	}
	else if (packge->funNum == 2) {
		PMmpack mmpack = packge->data;
		status = ReadR3MemoryVirtualMemory(mmpack->pid, mmpack->buffer, mmpack->readAddr, mmpack->size);	
	}
	switch (packge->funNum)
	{
		case 3: {
			PMmpack mmpack = packge->data;
			status = ReadR3MemoryMdl(mmpack->pid, mmpack->buffer, mmpack->readAddr, mmpack->size);
			break;
		}
		case 4: {
			PQUERYR3MODULE  mmpack = packge->data;
			status = GetR3ModuleAddr(mmpack->pid, mmpack->ModuleName);
			break;
		}
		case 5: {
			PQUERYR3MODULE  mmpack = packge->data;
			status = GetR3ModuleAddr64(mmpack->pid, mmpack->ModuleName);
			break;
		}
		case 6: {
			//test 
			DbgPrint("ͨ������\n");
			PSuspendThreadStruct  proceeptProcess = packge->data;
			status = ThreadHijackInject(proceeptProcess->dwThreadId, proceeptProcess->dwStartAddr32);
			DbgPrint("TEST ErrorCode:%x\n", status);
			break;
		}
		case 7: {
			//��ѯָ�������ڴ���Ϣ
			PProcessMemInfomation Mminfo = packge->data;
			status = QueryProcessMemory(Mminfo->pid, Mminfo->BaseAddress, Mminfo->pmyMemInfo, Mminfo->bufferSize);
			break;
		}
		case 8: {
			//����ָ������ ����ж��ʱ��������
			PPROCEPTPROCESS proceeptProcess = packge->data;
			ProtectProcess(proceeptProcess->PID);
			break;
		}
		case 9: {
			//ָ������ȥ���� ����ж��ʱ�ָ�����
			PPROCEPTPROCESS proceeptProcess = packge->data;
			status = PathProtectProcess(proceeptProcess->PID);
			break;
		}
		case 10: {
			//��ֹ���̴���
			PVOID64 data = packge->data;
			status = StopCreateProcess(data);
			break;
		}
		case 11: {
			//win10 x64  �������(pass��Ȩ)
		
		}

	}
	return status;
}












NTSTATUS newQueryFun(ULONG64 arg1, ULONG64 arg2){
	PMESSAGE_PACKAGE package = arg2;
	if (MmIsAddressValid(arg2)) {

		if (package->flag == 1234) {
			package->result = DispatchCallEntry(package);
			return;
		}
		else {
			if (oldQueryFun != NULL) {
				return oldQueryFun(arg1, arg2);
			}
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS newSetFun(ULONG64 arg1, ULONG64 arg2) {
	PMESSAGE_PACKAGE package = arg2;
	if (MmIsAddressValid(arg2)) {

		if (package->flag == 1234) {
			DispatchCallEntry(package);
			return package->result;
		}
		else {
			if (oldSetFun != NULL) {
				return oldSetFun(arg1, arg2);
			}
		}
	}
	return STATUS_SUCCESS;
}
NTSTATUS RegCallBack()
{
	/*
	
	
	WIN7����δ�޸���������δ�޸ġ���Ҫʹ��
	
		
	
	*/
	UNICODE_STRING funName = RTL_CONSTANT_STRING(L"ExRegisterAttributeInformationCallback");
	PVOID64 funaddr = MmGetSystemRoutineAddress(&funName);
	ULONG offset = *(PULONG)((ULONG64)funaddr + 0x10);
	AttributeInformation = (PULONG64)((ULONG64)funaddr + 0xd + 7+offset);
	//����
	oldQueryFun = AttributeInformation[0];
	oldSetFun = AttributeInformation[1];
	//���
	AttributeInformation[0] = 0;
	AttributeInformation[1] = 0;
	regCallBack = funaddr;
	RWCALL_BACK_FUN rwCallBack;
	rwCallBack.ExpDisQueryAttributeInformation = newQueryFun;
	rwCallBack.ExpDisSetAttributeInformation = newSetFun;
	NTSTATUS result =  regCallBack(&rwCallBack);
	if (NT_SUCCESS(result)) {
		DbgPrint("�ص���װ�ɹ�\n");
	}
	else
	{
		DbgPrint("�ص���װʧ��\n");
	}
	return STATUS_SUCCESS;
}
void UnloadCallBack() {
	if (AttributeInformation == NULL) {
		DbgPrint("�ص�ж��ʧ��\n");
		return;
	}
	AttributeInformation[0] = oldQueryFun;
	AttributeInformation[1] = oldSetFun;
	DbgPrint("�ص���ж��\n");

}