#include"ntifs.h"
#include"MmRw.h"
#include"ModuleUtil.h"
#include"processUtil.h"
//注册通信回调函数
NTSTATUS RegCallBack();
void UnloadCallBack();
typedef NTSTATUS(*MyExpDisQueryAttributeInformation)(ULONG64 arg1, ULONG64 arg2);
typedef struct _MESSAGE_PACKAGE {
	ULONG64 flag;
	ULONG64 funNum;
	ULONG64 data;
	ULONG64 dataSize;
	ULONG64 result;
}MESSAGE_PACKAGE,*PMESSAGE_PACKAGE;
typedef struct _RWCALL_BACK_FUN {
	MyExpDisQueryAttributeInformation ExpDisQueryAttributeInformation;
	MyExpDisQueryAttributeInformation ExpDisSetAttributeInformation;
}RWCALL_BACK_FUN,* PRWCALL_BACK_FUN;
typedef NTSTATUS(*_ExRegisterAttributeInformationCallback)(PRWCALL_BACK_FUN arg1);
NTSTATUS DispatchCallEntry(PMESSAGE_PACKAGE packge);