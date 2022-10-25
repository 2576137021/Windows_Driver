#include"ntifs.h"
typedef NTSTATUS (*PsSuspendThread)(
     PETHREAD Thread,
    PULONG PreviousSuspendCount
);
typedef NTSTATUS(*PsResumeThread)(
    PETHREAD Thread,
    PULONG PreviousSuspendCount
);
typedef struct _SuspendThreadStruct {
    DWORD32 dwThreadId;
    DWORD32 dwStartAddr32;
    DWORD64 dwStartAddr64;
}SuspendThreadStruct,* PSuspendThreadStruct;


NTSTATUS SuspendThread(DWORD32 dwThreadId);
NTSTATUS ResumeThread(DWORD32 dwThreadId);
NTSTATUS ThreadHijackInject(DWORD32 dwThreadId, DWORD32 dwStartAddr32);