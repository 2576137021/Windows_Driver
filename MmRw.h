#include"ntifs.h"
#include"windowsApi.h"
/*
pid:目标进程pid
buffer:存放读取的数据
readAddr:要读取的起始地址
size:要读取的大小
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
//切换成目标Cr3后可使用mdl方式映射虚拟地址
PVOID64 MapperMdl(PVOID64 readAddr, ULONG size, PMDL* mdl);
//修改内存属性
PVOID64 Get_NtProtectVirtualMemory();


