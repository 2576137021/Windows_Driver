#include"ntifs.h"
#include"windowsApi.h"
/*
pid:Ŀ�����pid
buffer:��Ŷ�ȡ������
readAddr:Ҫ��ȡ����ʼ��ַ
size:Ҫ��ȡ�Ĵ�С
*/
typedef struct _Mmpack {
	ULONG pid;
	PVOID64 buffer;
	PVOID64 readAddr;
	ULONG size;
}Mmpack,*PMmpack;

NTSTATUS ReadR3Memory(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size);
NTSTATUS ReadR3MemoryVirtualMemory(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size);
NTSTATUS ReadR3MemoryMdl(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size);
//�л���Ŀ��Cr3���ʹ��mdl��ʽӳ�������ַ
PVOID64 MapperMdl(PVOID64 readAddr, ULONG size, PMDL* mdl);
//�޸��ڴ�����
PVOID64 Get_NtProtectVirtualMemory();


