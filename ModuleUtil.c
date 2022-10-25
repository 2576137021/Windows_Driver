#include"ModuleUtil.h"
#include"windowsApi.h"

//˽�з���

/*
������:SearchSection64
����:�����ں�ģ���������ʼ��ַ�ͽ�����ַ
����1:�ں�ģ����ʼ��ַ
����2:��������
����3:����ں�ģ���������ʼ��ַ�ͽ�����ַ
����ֵ:NTSTATUS
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
//���з���
NTSTATUS GetR0ModuleAddr64(CHAR* moduleName, PModul_info moduleinfor) {
	//��ȡ��һ���ں�ģ����Ϣ
	ULONG64 retLen = 0;
	//��ȡ���ؽ���Ĵ�С
	ZwQuerySystemInformation(SystemModuleInformation, NULL,0, &retLen);
	//���ݽ�������ڴ�
	PSYSTEM_MODULE_INFORMATION64 moduleInfo  = ExAllocatePool(NonPagedPool, retLen);
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, moduleInfo, retLen, &retLen);
	if (!NT_SUCCESS(status)) {
		ExFreePool(moduleInfo);
		DbgPrint("��ѯģ����Ϣʧ��\n");
		return 1;
	}
	//ѭ���Ƚ�ģ������
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
		DbgPrint("δ�ҵ�ָ��ģ��\n");
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
		DbgPrint("��ȡģ���ַʧ��\n");
		return CodeAddr;
	}
	if (!MmIsAddressValid(moduleInfo.ImageBaseAddress)) {

		DbgPrint("ģ���ַ��Ч\n");
		return CodeAddr;
	}
	//�������������,����������ʼ��ַ�����εĴ�С
	if (SectionName!=NULL&&(MmIsAddressValid(SectionName))) {
		PE_SECTIONINFO sectionInfo = { 0 };
		status = SearchSection64(moduleInfo.ImageBaseAddress, SectionName, &sectionInfo);
		if (!NT_SUCCESS(status)) {
			DbgPrint("��ȡ���ε�ַʧ��\n");
		}
		else
		{
			DbgPrint("��ȡ���ε�ַ�ɹ�\n");
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
		DbgPrint("δ�ҵ�������\n");
		return CodeAddr;
	}
	DbgPrint("���������ҵ� %p\n", CodeAddr);
	return CodeAddr;
}
NTSTATUS GetR3ModuleAddr(ULONG pid,char* ModuleName) {
	//�ڹҿ�֮ǰת���ַ��� �������ں˿ռ䱣���ַ�����
	UNICODE_STRING cmpMoudle;
	ANSI_STRING cmpModuleName ;
	NTSTATUS ntstatus;
	//32�ṹ���ת������������64��ANSI_STRING��UNICODE_STRING
	RtlInitAnsiString(&cmpModuleName, ModuleName);
	ntstatus = RtlAnsiStringToUnicodeString(&cmpMoudle, &cmpModuleName, TRUE);
	if (!NT_SUCCESS(ntstatus))return;
	//�ҿ�����
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status)&& !MmIsAddressValid(ModuleName)) {
		RtlFreeUnicodeString(&cmpMoudle);
		return NULL;
	}
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess, &apcState);
	//��ȡpeb
	PPEB pPeb = PsGetProcessWow64Process(targetProcess);
	if (pPeb==NULL) {
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("��ȡPEBʧ��,�ú���ֻ֧��32λ����\n");
		return NULL;
	}
	//��λ�������һ���ڵ�  ���һ���ٲ���,��Ȼ����ȡһ��Flink��ֵ
	LIST_ENTRY32 loadList = ((PPEB_LDR_DATA)pPeb->ProcessEnvironmentBlock)->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY ldrData = loadList.Flink;

	//���Դ�С�Ƚ�
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
	//����
	RtlFreeUnicodeString(&cmpMoudle);
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);


	


}
/*
�ú�����������
ModuleName �ĵ�ַ����ʧЧ
*/
NTSTATUS GetR3ModuleAddr64(ULONG pid, char* ModuleName)
{
	//�ڹҿ�֮ǰת���ַ��� �������ں˿ռ䱣���ַ�����
	UNICODE_STRING64 cmpMoudle;
	ANSI_STRING64 cmpModuleName;
	NTSTATUS ntstatus;
	//32�ṹ���ת������������64��ANSI_STRING��UNICODE_STRING
	RtlInitAnsiString(&cmpModuleName, ModuleName);
	ntstatus = RtlAnsiStringToUnicodeString(&cmpMoudle, &cmpModuleName, TRUE);
	if(!NT_SUCCESS(ntstatus))return;
	//�ҿ�����
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status) && !MmIsAddressValid(ModuleName)) {
		RtlFreeUnicodeString(&cmpMoudle);
		return ;
	}
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess, &apcState);
	//ͨ�����̶���(Eprocess)��ȡPPEB
	PPEB64 peb64 = *(ULONG64*)((char*)targetProcess + 0x338);
	if (peb64 == NULL) {
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("��ȡPEBʧ��,�ú���ֻ֧��64λ����\n");
		return NULL;
	}

	if (!MmIsAddressValid(peb64))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("��ȡPEBʧ��\n");
		return MODULEUTILE_ERROR;
	}
	PPEB_LDR_DATA64 pebLdrData64 = peb64->Ldr;
	if (!MmIsAddressValid(pebLdrData64))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("��ȡPPEB_LDR_DATA64ʧ��\n");
		return MODULEUTILE_ERROR;
	}
	LIST_ENTRY64 list = pebLdrData64->InLoadOrderModuleList;
	PLDR_DATA_TABLE_ENTRY64 ldrDataTable = list.Flink;
	if (!MmIsAddressValid(ldrDataTable))
	{
		KeUnstackDetachProcess(&apcState);
		ObDereferenceObject(targetProcess);
		RtlFreeUnicodeString(&cmpMoudle);
		DbgPrint("��ȡPLDR_DATA_TABLE_ENTRYʧ��\n");
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
	//����
	RtlFreeUnicodeString(&cmpMoudle);
	KeUnstackDetachProcess(&apcState);
	ObDereferenceObject(targetProcess);
	return TRUE;
}


