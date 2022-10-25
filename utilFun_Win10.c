#include"utilFun_Win10.h"
//保存原先的方法地址
MyFun OldFunAddr = 0;
ULONG64* callBackAddr = 0;
NTSTATUS __fastcall NewFun(ULONG64 arg1,ULONG64* arg2,ULONG64* arg3) {
	PMESSAGE_PACKAGE messagePack = arg1;
	__try {
		ProbeForWrite((PVOID64)messagePack, sizeof(PMESSAGE_PACKAGE), 4);
		if (messagePack->flag == 1234) {
			DbgPrint("功能号:%d\n", messagePack->funNum);
			NTSTATUS state =  DispatchCallEntry(messagePack);
			return -1;
		}
		else {
			if (OldFunAddr != NULL) {
				return OldFunAddr(arg1, arg2, arg3);
			}
		}
	}
	__except(1){
		DbgPrint("指针异常或被其他调用\n");
		return OldFunAddr(arg1, arg2, arg3);
	}
	return STATUS_SUCCESS;
}
NTSTATUS RegCallBackWin10()
{

	//定位通信方法地址
	CHAR moduleName[] = "ntoskrnl.exe";
	Modul_info  moduleInfo = { 0 };
	UCHAR ida_chars[] =
	{
	  0x48, 0x8B, 0x05, 0xcc, 0xcc, 0xcc, 0xcc, 0x75, 0x07, 0x48,
	  0x8B, 0x05, 0xcc, 0xcc, 0xcc, 0xcc, 0xE8, 0xcc, 0xcc, 0xcc,
	  0xcc, 0x8B, 0xC8, 0x85, 0xC0, 0x78, 0x40, 0x48, 0x8B, 0x44,
	  0x24, 0x20, 0x48, 0x89, 0xcc, 0x48, 0x85, 0xDB, 0x74, 0x08,
	  0x48, 0x8B, 0x44, 0x24, 0x28, 0x48, 0x89, 0x03, 0xEB, 0x29,
	  0x8B, 0xC8, 0xEB, 0x25, 0xEB, 0x25
	};
	char sectionName[] = "PAGE";
	ULONG64 funAddr= SearchCode(moduleName, sectionName, ida_chars, sizeof(ida_chars));
	if (!MmIsAddressValid(funAddr)) {
		return	FUN_ADDR_ERROR;
	}
	//这里要使用有符号 因为偏移有正负
	LONG offset = *(LONG*)(funAddr + 3);
	ULONG64 nextCode = funAddr + 7;
	callBackAddr = nextCode + offset;
	if (!MmIsAddressValid(callBackAddr)) {
		DbgPrint("回调地址错误\n");
		return FUN_ADDR_ERROR;
	}
	OldFunAddr = *callBackAddr;
	DbgPrint("原始地址:%lp\n", OldFunAddr);
	
	*callBackAddr = NewFun;
	DbgPrint("现在地址:%lp\n", *callBackAddr);
	DbgPrint("Win10 回调安装成功\n");
	return STATUS_SUCCESS;
}

void UnloadCallBackWin10()
{
	if (MmIsAddressValid(callBackAddr)) {
		*callBackAddr = OldFunAddr;
		DbgPrint("Win10通信已摘除");
		DbgPrint("现在地址:%lp\n", *callBackAddr);
	}
}

