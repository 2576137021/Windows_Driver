#include"ntifs.h"
#include"uitlFun_Win7.h"
#define FUN_ADDR_ERROR -1;

//ͨ�Žṹ��
//ע��win10ͨ�ź���
NTSTATUS RegCallBackWin10();
//ж��ͨ�ź���
void UnloadCallBackWin10();
//��������
typedef NTSTATUS(*MyFun)(ULONG64 arg1, ULONG64* arg2, ULONG64* arg3);
//Path�ص���������
void pathCallBack(PDRIVER_OBJECT pobj);
void unPathCallBack(PDRIVER_OBJECT pobj);
