#include<ntifs.h>
/*
功能:通过复制一份eprocess,修改进程名称,pass句柄降权
参数1:被提权的进程(如CE,xdbg等)
参数2:目标进程pid
*/
NTSTATUS passHandleDown(DWORD32 dwPid,DWORD32 dwTargetPid);