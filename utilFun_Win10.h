#include"ntifs.h"
#include"uitlFun_Win7.h"
#define FUN_ADDR_ERROR -1;

//通信结构体
//注册win10通信函数
NTSTATUS RegCallBackWin10();
//卸载通信函数
void UnloadCallBackWin10();
//方法定义
typedef NTSTATUS(*MyFun)(ULONG64 arg1, ULONG64* arg2, ULONG64* arg3);
//Path回调函数限制
void pathCallBack(PDRIVER_OBJECT pobj);
void unPathCallBack(PDRIVER_OBJECT pobj);
