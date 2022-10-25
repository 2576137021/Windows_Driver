#include"uitlFun_Win7.h"
#include"ThreadUtil.h"
MyExpDisQueryAttributeInformation oldQueryFun = NULL;
MyExpDisQueryAttributeInformation oldSetFun = NULL;
_ExRegisterAttributeInformationCallback regCallBack = NULL;
PULONG64 AttributeInformation = 0;
NTSTATUS status = 0;
//功能中转站
NTSTATUS DispatchCallEntry(PMESSAGE_PACKAGE packge) {
	DbgPrint("已接收到三环请求\n");
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
			DbgPrint("通信正常\n");
			PSuspendThreadStruct  proceeptProcess = packge->data;
			status = ThreadHijackInject(proceeptProcess->dwThreadId, proceeptProcess->dwStartAddr32);
			DbgPrint("TEST ErrorCode:%x\n", status);
			break;
		}
		case 7: {
			//查询指定进程内存信息
			PProcessMemInfomation Mminfo = packge->data;
			status = QueryProcessMemory(Mminfo->pid, Mminfo->BaseAddress, Mminfo->pmyMemInfo, Mminfo->bufferSize);
			break;
		}
		case 8: {
			//保护指定进程 驱动卸载时保护结束
			PPROCEPTPROCESS proceeptProcess = packge->data;
			ProtectProcess(proceeptProcess->PID);
			break;
		}
		case 9: {
			//指定进程去保护 驱动卸载时恢复保护
			PPROCEPTPROCESS proceeptProcess = packge->data;
			status = PathProtectProcess(proceeptProcess->PID);
			break;
		}
		case 10: {
			//阻止进程创建
			PVOID64 data = packge->data;
			status = StopCreateProcess(data);
			break;
		}
		case 11: {
			//win10 x64  拷贝句柄(pass降权)
		
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
	
	
	WIN7代码未修复，特征码未修改。不要使用
	
		
	
	*/
	UNICODE_STRING funName = RTL_CONSTANT_STRING(L"ExRegisterAttributeInformationCallback");
	PVOID64 funaddr = MmGetSystemRoutineAddress(&funName);
	ULONG offset = *(PULONG)((ULONG64)funaddr + 0x10);
	AttributeInformation = (PULONG64)((ULONG64)funaddr + 0xd + 7+offset);
	//保存
	oldQueryFun = AttributeInformation[0];
	oldSetFun = AttributeInformation[1];
	//清空
	AttributeInformation[0] = 0;
	AttributeInformation[1] = 0;
	regCallBack = funaddr;
	RWCALL_BACK_FUN rwCallBack;
	rwCallBack.ExpDisQueryAttributeInformation = newQueryFun;
	rwCallBack.ExpDisSetAttributeInformation = newSetFun;
	NTSTATUS result =  regCallBack(&rwCallBack);
	if (NT_SUCCESS(result)) {
		DbgPrint("回调安装成功\n");
	}
	else
	{
		DbgPrint("回调安装失败\n");
	}
	return STATUS_SUCCESS;
}
void UnloadCallBack() {
	if (AttributeInformation == NULL) {
		DbgPrint("回调卸载失败\n");
		return;
	}
	AttributeInformation[0] = oldQueryFun;
	AttributeInformation[1] = oldSetFun;
	DbgPrint("回调已卸载\n");

}