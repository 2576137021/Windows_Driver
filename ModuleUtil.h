#include "ntifs.h"
#include<ntimage.h>
#pragma pack (4)
#define MODULEUTILE_ERROR 0x1;
//系统结构体
//32位PEB结构体
typedef struct _LDR_DATA_TABLE_ENTRY {
    LIST_ENTRY32 InLoadOrderLinks;
    LIST_ENTRY32 InMemoryOrderLinks;
    LIST_ENTRY32 InInitializationOrderLinks;
    ULONG DllBase;
    ULONG EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING32 FullDllName;
    UNICODE_STRING32 BaseDllName;
    ULONG Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY32 HashLinks;
        struct {
            ULONG SectionPointer;
            ULONG CheckSum;
        };
    };
    union {
        struct {
            ULONG TimeDateStamp;
        };
        struct {
            ULONG LoadedImports;
        };
    };
    ULONG* EntryPointActivationContext;
    ULONG PatchInformation;

} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;
typedef struct _PEB_LDR_DATA {
    ULONG Length;
    ULONG Initialized;
    ULONG SsHandle;
    LIST_ENTRY32 InLoadOrderModuleList;
    LIST_ENTRY32 InMemoryOrderModuleList;
    LIST_ENTRY32 InInitializationOrderModuleList;
    ULONG EntryInProgress;
} PEB_LDR_DATA, * PPEB_LDR_DATA;
typedef struct _PEB {
    ULONG32 a1;
    ULONG32 a2;
    ULONG32 a3;
    ULONG32 ProcessEnvironmentBlock;
}PEB, *PPEB;
typedef struct _QUERYR3MODULE{
	ULONG64 pid;
	char* ModuleName;
}QUERYR3MODULE, * PQUERYR3MODULE;
//64位PEB结构体
typedef struct _PEB_LDR_DATA64 {
    ULONG32 a1;
    ULONG32 a2;
    ULONG64 a3;
    LIST_ENTRY64 InLoadOrderModuleList;
}PEB_LDR_DATA64, * PPEB_LDR_DATA64;
typedef struct _PEB64 {
    ULONG64 a1;
    ULONG64 a2;
    ULONG64 a3;
    PPEB_LDR_DATA64 Ldr;
}PEB64, * PPEB64;
typedef struct _LDR_DATA_TABLE_ENTRY64 {
    LIST_ENTRY64 InLoadOrderLinksl;
    LIST_ENTRY64 InMemoryOrderLinks;
    LIST_ENTRY64 InInitializationOrderLinks;
    PVOID64 DllBase;
    PVOID64 EntryPoint;
    ULONG64 SizeOfImage;
    UNICODE_STRING64 FullDllName;
    UNICODE_STRING64 BaseDllName;
    ULONG32 Flags;
    USHORT LoadCount;
    USHORT TlsIndex;
    union {
        LIST_ENTRY64 HashLinks;
        struct {
            ULONG64 SectionPointer;
            ULONG64 CheckSum;
        };
    };
}LDR_DATA_TABLE_ENTRY64, * PLDR_DATA_TABLE_ENTRY64;
//模块结构体 系统
typedef struct _SYSTEM_MODULE_INFORMATION_ENTRY64 {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG32 ImageSize;
    ULONG32 Flags;
    USHORT Index;
    USHORT Unknown;
    USHORT LoadCount;
    USHORT ModuleNameOffset;
    CHAR ImageName[256];
} SYSTEM_MODULE_INFORMATION_ENTRY64, * PSYSTEM_MODULE_INFORMATION_ENTRY64;
typedef struct _SYSTEM_MODULE_INFORMATION64 {
    ULONG64                ModulesCount;
    SYSTEM_MODULE_INFORMATION_ENTRY64        Modules[0];
} SYSTEM_MODULE_INFORMATION64, * PSYSTEM_MODULE_INFORMATION64;

//自定义结构体
//模块查询结构体 
typedef struct _Modul_info {
    ULONG64              ImageBaseAddress;
    ULONG64                ImageSize;
}Modul_info,* PModul_info;
//pe区段信息输出结构体
typedef struct _PE_SECTIONINFO {
    ULONG64              SectionBaseAddress;
    ULONG64               SectionImageSize;
}PE_SECTIONINFO,* PPE_SECTIONINFO;


NTSTATUS GetR3ModuleAddr(ULONG pid, char* ModuleName);
NTSTATUS GetR3ModuleAddr64(ULONG pid, char* ModuleName);
NTSTATUS GetR0ModuleAddr64(CHAR* moduleName, PModul_info moduleinfor);
/*
功能:搜索内核空间特征码
参数1:内核模块名称
参数2:区段名称
参数3:特征码字节数组 
参数4:特征码数组长度
返回值:特征码起始地址
注解:特征码搜索支持通配符0xcc,如果不知道区段名称请填写NULL.
*/
ULONG64 SearchCode(char* moduleName, char* SectionName, UCHAR code[], size_t codelen);