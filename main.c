#include"utilFun_Win10.h"
int WIN10 = 0;
int WIN7 = 0;
void Driverunload(PDRIVER_OBJECT object) {
	if (WIN7) {
		UnloadCallBack();
	}
	else
	{
		//去除阻止进程创建回调
		UnStopCreateProcess();
		//去除回调保护
		UnProtectProcess();
		//去除去回调保护
		UnPathProtectProcess();
		//卸载通信
		UnloadCallBackWin10();
	}
	DbgPrint("驱动已卸载\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING regPath) {
	object->DriverUnload = Driverunload;
	DbgPrint("驱动已安装\n");
	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)object->DriverSection;
	ldr->Flags |= 0x20;
	//判断操作系统
	RTL_OSVERSIONINFOEXW osInformation;
	osInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion(&osInformation);
	DbgPrint("版本号：%d\n",osInformation.dwBuildNumber);
	if (osInformation.dwBuildNumber<10000) {
		WIN7 = 1;
		RegCallBack();
	}
	else {
		WIN10 = 1;
		RegCallBackWin10();
	}


	
	return STATUS_SUCCESS;
}
