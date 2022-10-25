#include"ModuleUtil.h"
#include"windowsApi.h"

//私有方法

/*
方法名:SearchSection64
功能:搜索内核模块的区段起始地址和结束地址
参数1:内核模块起始地址
参数2:区段名称
参数3:输出内核模块的区段起始地址和结束地址
返回值:NTSTATUS
*/
NTSTATUS SearchSection64(ULONG64 ImageBaseAddress,char* SectionName, PPE_SECTIONINFO sectionInfo) {

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)ImageBaseAddress;
	PIMAGE_NT_HEADERS64 pNtHeader = ImageBaseAddress + pDosHeader->e_lfanew;
	PIMAGE_FILE_HEADER pFileHeader = &pNtHeader->FileHeader;
	USHORT numberOfSection = pFileHeader->NumberOfSections;
	PIMAGE_SECTION_HEADER pFirstSection = IMAGE_FIRST_SECTION(pNtHeader);
	for (size_t i = 0; i < numberOfSection; i++)
	{
		if (!strncmp(SectionName, pFirstSection->Name,8)) {
			sectionInfo->SectionBaseAddress = pFirstSection->VirtualAddress+ ImageBaseAddress;
			sectionInfo->SectionImageSize = pFirstSection->SizeOfRawData;
			return STATUS_SUCCESS;
		}
		pFirstSection++;
	}
	return -1;
}
//公有方法
NTSTATUS GetR0ModuleAddr64(CHAR* moduleName, PModul_info moduleinfor) {
	//获取第一个内核模块信息
	ULONG64 retLen = 0;
	//获取返回结果的大小
	ZwQuerySystemInformation(SystemModuleInformation, NULL,0, &retLen);
	//根据结果申请内存
	PSYSTEM_MODULE_INFORMATION64 moduleInfo  = ExAllocatePool(NonPagedPool, retLen);
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, retLen, &retLen);
	if (!NT_SUCCESS(status)) {
		ExFreePool(moduleInfo);
		DbgPrint("查询模块信息失败\n");
		return 1;
	}
	//循环比较模块名称
	PSYSTEM_MODULE_INFORMATION_ENTRY64 sysModule = NULL;
	for (size_t i = 0; i <= moduleInfo->ModulesCount; i++)
	{
		sysModule = &(moduleInfo->Modules[i]);
		if (!MmIsAddressValid(sysModule)) {
			continue;
		}
		//DbgPrint("ImageName:%s", sysModule->ImageName);
		if (strstr(sysModule->ImageName, moduleName)) {
			//DbgPrint("Module Find it\n");
			moduleinfor->ImageBaseAddress = sysModule->ImageBase;
			moduleinfor->ImageSize = sysModule->ImageSize;
			ExFreePool(moduleInfo);
			return 0;
		}
		DbgPrint("未找到指定模块\n");
	}
	ExFreePool(moduleInfo);
	return 1;
}
ULONG64 SearchCode(char* moduleName, char* SectionName, UCHAR code[],size_t codelen)
{
	ULONG64 CodeAddr = 0;
	UCHAR flag = 0xcc;
	Modul_info moduleInfo = { 0 };
	NTSTATUS status =  GetR0ModuleAddr64(moduleName, &moduleInfo);
	if (!NT_SUCCESS(status)) {
		DbgPrint("获取模块地址失败\n");
		return CodeAddr;
	}
	if (!MmIsAddressValid(moduleInfo.ImageBaseAddress)) {

		DbgPrint("模块地址无效\n");
		return CodeAddr;
	}
	//如果存在区段名,则找区段起始地址和区段的大小
	if (SectionName!=NULL&&(MmIsAddressValid(SectionName))) {
		PE_SECTIONINFO sectionInfo = { 0 };
		status = SearchSection64(moduleInfo.ImageBaseAddress, SectionName, &sectionInfo);
		if (!NT_SUCCESS(status)) {
			DbgPrint("获取区段地址失败\n");
		}
		else
		{
			DbgPrint("获取区段地址成功\n");
			moduleInfo.ImageBaseAddress = sectionInfo.SectionBaseAddress;
			moduleInfo.ImageSize = sectionInfo.SectionImageSize;
		}
	}
	SIZE_T rect = 0;
	PEPROCESS pProcess = IoGetCurrentProcess();
	MmCopyVirtualMemory(pProcess, moduleInfo.ImageSize, pProcess, moduleInfo.ImageSize, 1, UserMode, &rect);
	for (size_t i = 0; i <=  moduleInfo.ImageSize-codelen; i++) {
		int temp = 0;
		for (size_t j = 0; j < codelen; j++)
		{
			UCHAR* pNowCode = (char*)(moduleInfo.ImageBaseAddress + i + j);
			if (pNowCode==NULL) {
				break;
			}
			if (!MmIsAddressValid(pNowCode)) {
				break;
			}
			UCHAR nowCode = *pNowCode;
			if (code[j] == flag) {
				temp = j;
				continue;
			}
			if (nowCode != code[j])break;
			temp = j;
		}
		if (temp== codelen - 1) {
			CodeAddr = moduleInfo.ImageBaseAddress + i;
			break;
		}
	}
	if (CodeAddr==0) {
		DbgPrint("未找到特征码\n");
		return CodeAddr;
	}
	DbgPrint("特征码已找到 %p\n", CodeAddr);
	return CodeAddr;
}
NTSTATUS GetR3ModuleAddr(ULONG pid,char* ModuleName) {
	//在挂靠之前转换字符串 并且在内核空间保存字符串。
	UNICODE_STRING cmpMoudle;
	ANSI_STRING cmpModuleName ;
	NTSTATUS ntstatus;
	//32结构体会转换出错，必须是64的ANSI_STRING、UNICODE_STRING
	RtlInitAnsiString(&cmpModuleName, ModuleName);
	ntstatus = RtlAnsiStringToUnicodeString(&cmpMoudle, &cmpModuleName, TRUE);
	if (!NT_SUCCESS(ntstatus))return;
	//挂靠进程
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status)&& !MmIsAddressValid(ModuleName)) {
		RtlFreeUnicodeString(&cmpMoudle);
		return NULL;
	}
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess, &apcState);
	//获取peb
	PPEB pPeb = PsGetProcessWow64Process(targetProcess);
	if (pPeb==NULL) {
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("获取PEB失败,该函数只支持32位进程\n");
		return NULL;
	}
	//定位到链表第一个节点  拆分一下再操作,不然会少取一次Flink的值
	LIST_ENTRY32 loadList = ((PPEB_LDR_DATA)pPeb->ProcessEnvironmentBlock)->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY ldrData = loadList.Flink;

	//忽略大小比较
	PLIST_ENTRY32 nextList = (PLIST_ENTRY32)ldrData;
	do
	{
		UNICODE_STRING32 temp = (((PLDR_DATA_TABLE_ENTRY)nextList)->BaseDllName);
		UNICODE_STRING64  baseDllName = { 0 };
		baseDllName.Buffer = temp.Buffer;
		baseDllName.Length = temp.Length;
		baseDllName.MaximumLength = temp.MaximumLength;
		if (!RtlCompareUnicodeString(&cmpMoudle, &baseDllName, TRUE)) {
			DbgPrint("DllName:%ws DllBase:%p\n", baseDllName.Buffer, ((PLDR_DATA_TABLE_ENTRY)nextList)->DllBase);
			break;
		}
		nextList = nextList->Flink;
	} while (nextList != ldrData);
	//清理
	RtlFreeUnicodeString(&cmpMoudle);
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);


	


}
/*
该函数存在隐患
ModuleName 的地址可能失效
*/
NTSTATUS GetR3ModuleAddr64(ULONG pid, char* ModuleName)
{
	//在挂靠之前转换字符串 并且在内核空间保存字符串。
	UNICODE_STRING64 cmpMoudle;
	ANSI_STRING64 cmpModuleName;
	NTSTATUS ntstatus;
	//32结构体会转换出错，必须是64的ANSI_STRING、UNICODE_STRING
	RtlInitAnsiString(&cmpModuleName, ModuleName);
	ntstatus = RtlAnsiStringToUnicodeString(&cmpMoudle, &cmpModuleName, TRUE);
	if(!NT_SUCCESS(ntstatus))return;
	//挂靠进程
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status) && !MmIsAddressValid(ModuleName)) {
		RtlFreeUnicodeString(&cmpMoudle);
		return ;
	}
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess, &apcState);
	//通过进程对象(Eprocess)获取PPEB
	PPEB64 peb64 = *(ULONG64*)((char*)targetProcess + 0x338);
	if (peb64 == NULL) {
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("获取PEB失败,该函数只支持64位进程\n");
		return NULL;
	}

	if (!MmIsAddressValid(peb64))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("获取PEB失败\n");
		return MODULEUTILE_ERROR;
	}
	PPEB_LDR_DATA64 pebLdrData64 = peb64->Ldr;
	if (!MmIsAddressValid(pebLdrData64))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("获取PPEB_LDR_DATA64失败\n");
		return MODULEUTILE_ERROR;
	}
	LIST_ENTRY64 list = pebLdrData64->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY64 ldrDataTable = list.Flink;
	if (!MmIsAddressValid(ldrDataTable))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("获取PLDR_DATA_TABLE_ENTRY失败\n");
		return MODULEUTILE_ERROR;
	}
	PLIST_ENTRY64 temp = list.Flink;
	while (temp->Flink!= ldrDataTable)
	{
		PLDR_DATA_TABLE_ENTRY64 tempDataTable = temp;
		UNICODE_STRING64 tempDllName = tempDataTable->BaseDllName;
		DbgPrint("DllName:%ws DllBase:%x \n", tempDllName.Buffer, tempDataTable->DllBase);
		if (!RtlCompareString(&tempDllName, &cmpMoudle,TRUE)) {
			DbgPrint("OK Found it\n");
			break;
		}
		temp = temp->Flink;
	}
	//清理
	RtlFreeUnicodeString(&cmpMoudle);
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);
	return TRUE;
}


