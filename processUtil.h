#include <ntifs.h>
#define R3ADDRESSERROR -1
#define MALLOCERROR -2

//结构体
//内存信息结构体，支持32位和64位
typedef struct _MYMEMORY_BASIC_INFORMATION {
	ULONG64  BaseAddress;
	ULONG64  AllocationBase;
	ULONG64  AllocationProtect;
	ULONG64	 PartitionId;
	ULONG64	 RegionSize;
	ULONG64  State;
	ULONG64  Protect;
	ULONG64	 Type;
} MYMEMORY_BASIC_INFORMATION, * PMYMEMORY_BASIC_INFORMATION;
typedef struct _ProcessMemInfomation {
	ULONG32 pid;
	PVOID64 BaseAddress;
	PMYMEMORY_BASIC_INFORMATION pmyMemInfo;
	ULONG64 bufferSize;
}ProcessMemInfomation, * PProcessMemInfomation;
/*
类型:结构体
对应函数:ProtectProcess
参数1:进程PID
*/
typedef struct _PROCEPTPROCESS {
	DWORD32 PID;
}PROCEPTPROCESS,*PPROCEPTPROCESS;
typedef struct _JmpEcx {
	PVOID64 FunAddr;
	DWORD32 PID;
}JmpEcx,*PJmpEcx;
/*
功能:查询内存页属性
参数1:进程PID
参数2:要查询的地址
参数3:接收查询结果的结构体
参数4:要查询地址的大小
返回值:NTSTATUS
注解:该函数只支持win10以上的系统。
*/
NTSTATUS QueryProcessMemory(DWORD32 PID, PVOID64 BaseAddress, PMYMEMORY_BASIC_INFORMATION pmyMemInfo, ULONG64 bufferSize);
/*
功能:保护指定进程
参数1:进程PID
注解:该函数只支持win10以上的系统。
*/
NTSTATUS ProtectProcess(DWORD32 PID);
/*
功能:取消保护
注解：驱动停止时自动调用
*/
NTSTATUS UnProtectProcess();
/*
功能:取消某进程的回调降权保护
参数1:进程PID
注解:该函数只支持win10以上的系统。
*/
NTSTATUS PathProtectProcess(DWORD32 PID);
NTSTATUS UnPathProtectProcess();

/*
功能:通过跳板隐藏模块信息
*/
PVOID64 SearchJmpEcx();
/*
功能:阻止指定进程创建
*/
NTSTATUS StopCreateProcess(char* imageName);
void UnStopCreateProcess();