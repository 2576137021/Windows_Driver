#include"utilFun_Win10.h"
int WIN10 = 0;
int WIN7 = 0;
void Driverunload(PDRIVER_OBJECT object) {
	if (WIN7) {
		UnloadCallBack();
	}
	else
	{
		//ȥ����ֹ���̴����ص�
		UnStopCreateProcess();
		//ȥ���ص�����
		UnProtectProcess();
		//ȥ��ȥ�ص�����
		UnPathProtectProcess();
		//ж��ͨ��
		UnloadCallBackWin10();
	}
	DbgPrint("������ж��\n");
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING regPath) {
	object->DriverUnload = Driverunload;
	DbgPrint("�����Ѱ�װ\n");
	PLDR_DATA_TABLE_ENTRY64 ldr;
	ldr = (PLDR_DATA_TABLE_ENTRY64)object->DriverSection;
	ldr->Flags |= 0x20;
	//�жϲ���ϵͳ
	RTL_OSVERSIONINFOEXW osInformation;
	osInformation.dwOSVersionInfoSize = sizeof(RTL_OSVERSIONINFOEXW);
	RtlGetVersion(&osInformation);
	DbgPrint("�汾�ţ�%d\n",osInformation.dwBuildNumber);
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
