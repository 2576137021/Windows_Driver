#include<ntifs.h>
/*
����:ͨ������һ��eprocess,�޸Ľ�������,pass�����Ȩ
����1:����Ȩ�Ľ���(��CE,xdbg��)
����2:Ŀ�����pid
*/
NTSTATUS passHandleDown(DWORD32 dwPid,DWORD32 dwTargetPid);