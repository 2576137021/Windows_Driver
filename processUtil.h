#include <ntifs.h>
#define R3ADDRESSERROR -1
#define MALLOCERROR -2

//�ṹ��
//�ڴ���Ϣ�ṹ�壬֧��32λ��64λ
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
����:�ṹ��
��Ӧ����:ProtectProcess
����1:����PID
*/
typedef struct _PROCEPTPROCESS {
	DWORD32 PID;
}PROCEPTPROCESS,*PPROCEPTPROCESS;
typedef struct _JmpEcx {
	PVOID64 FunAddr;
	DWORD32 PID;
}JmpEcx,*PJmpEcx;
/*
����:��ѯ�ڴ�ҳ����
����1:����PID
����2:Ҫ��ѯ�ĵ�ַ
����3:���ղ�ѯ����Ľṹ��
����4:Ҫ��ѯ��ַ�Ĵ�С
����ֵ:NTSTATUS
ע��:�ú���ֻ֧��win10���ϵ�ϵͳ��
*/
NTSTATUS QueryProcessMemory(DWORD32 PID, PVOID64 BaseAddress, PMYMEMORY_BASIC_INFORMATION pmyMemInfo, ULONG64 bufferSize);
/*
����:����ָ������
����1:����PID
ע��:�ú���ֻ֧��win10���ϵ�ϵͳ��
*/
NTSTATUS ProtectProcess(DWORD32 PID);
/*
����:ȡ������
ע�⣺����ֹͣʱ�Զ�����
*/
NTSTATUS UnProtectProcess();
/*
����:ȡ��ĳ���̵Ļص���Ȩ����
����1:����PID
ע��:�ú���ֻ֧��win10���ϵ�ϵͳ��
*/
NTSTATUS PathProtectProcess(DWORD32 PID);
NTSTATUS UnPathProtectProcess();

/*
����:ͨ����������ģ����Ϣ
*/
PVOID64 SearchJmpEcx();
/*
����:��ָֹ�����̴���
*/
NTSTATUS StopCreateProcess(char* imageName);
void UnStopCreateProcess();