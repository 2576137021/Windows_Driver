#include"ntifs.h"
#include"MmRw.h"
#include"ModuleUtil.h"
NTSTATUS state;
//检查参数
NTSTATUS MmCheck(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size) {
	if (readAddr >= MmHighestUserAddress || (ULONG64)readAddr + size > MmHighestUserAddress) {
		return STATUS_ACCESS_VIOLATION;
	}
	if (size <= 0) {

		return STATUS_INVALID_PARAMETER_4;
	}
	if (!MmIsAddressValid(buffer)) {

		return STATUS_INVALID_PARAMETER_2;
	}
	return STATUS_SUCCESS;
}
//进程挂靠读取内存
NTSTATUS ReadR3Memory(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size) {
	state = MmCheck(pid, buffer, readAddr, size);
	if (!NT_SUCCESS(state)) {
		return state;
	}
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status)) 
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	DWORD32 oldCr3 = *(DWORD32*)((char*)targetProcess + 0x28);
	DbgPrint("目标进程Cr3:%x\n", oldCr3);
	PVOID r0buffer = ExAllocatePool(NonPagedPool, size);
	if (r0buffer == NULL) {
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}
	memset(buffer, 0, size);
	memset(r0buffer, 0, size);
	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess,&apcState);
	if (!MmIsAddressValid(readAddr)){
		ObDereferenceObject(targetProcess);
		return STATUS_INVALID_PARAMETER_3;
	}
	memcpy(r0buffer, readAddr, size);
	KeUnstackDetachProcess(&apcState);
	memcpy(buffer, r0buffer, size);
	ExFreePool(r0buffer);
	ObDereferenceObject(targetProcess);
	DbgPrint("内存读取成功\n");
	return STATUS_SUCCESS;

	

}
//MmCopyVirtualMemory 读取内存
NTSTATUS ReadR3MemoryVirtualMemory(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size) {
	state = MmCheck(pid, buffer, readAddr, size);
	if (!NT_SUCCESS(state)) {
		return state;
	}
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		return STATUS_INVALID_PARAMETER_1;
	}
	DWORD32 oldCr3 = *(DWORD32*)((char*)targetProcess + 0x28);
	PVOID r0buffer = ExAllocatePool(NonPagedPool, size);
	if (r0buffer == NULL) {
		ObDereferenceObject(targetProcess);
		return STATUS_UNSUCCESSFUL;
	}
	memset(buffer, 0, size);
	memset(r0buffer, 0, size);
	size_t fullSize = 0;
	
	NTSTATUS state = MmCopyVirtualMemory(targetProcess, readAddr, IoGetCurrentProcess(), r0buffer,size, KernelMode, &fullSize);

	memcpy(buffer, r0buffer, size);
	ExFreePool(r0buffer);
	ObDereferenceObject(targetProcess);
	DbgPrint("内存读取完成\n");
	return state;

}
//mdl映射 可读可写
PVOID64 MapperMdl(PVOID64 readAddr, ULONG size,PMDL* mdl) {
	NTSTATUS ntStatus;
	PMDL MdlAddr = IoAllocateMdl(readAddr, size, FALSE, FALSE, NULL);
	PVOID64 mapperdAddr = NULL;
	if (MdlAddr == NULL) {
		DbgPrint("MDl内存分配失败\n");
		return NULL;
	}
	//锁定内存页
	try {
		MmProbeAndLockPages(MdlAddr, UserMode, IoWriteAccess);
	}except(EXCEPTION_EXECUTE_HANDLER) {
		ntStatus = GetExceptionCode();
		DbgPrint("Exception while locking inBuf 0X%08X in METHOD_NEITHER\n",
			ntStatus);
		IoFreeMdl(MdlAddr);
		return NULL;
	}
	MEMORY_CACHING_TYPE cachingType = { 0 };
	__try {
		 mapperdAddr = MmMapLockedPagesSpecifyCache(MdlAddr, KernelMode, MmNonCached, readAddr, FALSE, NormalPagePriority);
	}
	__except (1) {
		DbgPrint("MDl映射失败\n");
		MmUnlockPages(MdlAddr);
		IoFreeMdl(MdlAddr);
		return NULL;
	}
	*mdl = MdlAddr;
	return mapperdAddr;
}

//进程挂靠 + Mdl
NTSTATUS ReadR3MemoryMdl(ULONG pid, PVOID64 buffer, PVOID64 readAddr, ULONG size)
{
	//进程挂靠
	state = MmCheck(pid, buffer, readAddr, size);
	if (!NT_SUCCESS(state)) {
		return state;
	}
	PEPROCESS targetProcess;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &targetProcess);
	if (!NT_SUCCESS(status))
	{
		return STATUS_INVALID_PARAMETER_1;
	}

	KAPC_STATE apcState = { 0 };
	KeStackAttachProcess(targetProcess, &apcState);
	if (!MmIsAddressValid(readAddr)) {
		ObDereferenceObject(targetProcess);
		return STATUS_INVALID_PARAMETER_3;
	}
	//映射mdl
	PMDL* mdl = ExAllocatePool(NonPagedPool,0x8);
	PVOID64 mapperAddr  = MapperMdl(readAddr, size, mdl);
	KeUnstackDetachProcess(&apcState);
	if (mapperAddr == NULL) {
		ExFreePool(mdl);
		ObDereferenceObject(targetProcess);
		return -1;
	}
	memcpy(buffer, mapperAddr, size);
	MmUnmapLockedPages(mapperAddr, *mdl);
	MmUnlockPages(*mdl);
	IoFreeMdl(*mdl);

	ObDereferenceObject(targetProcess);
	ExFreePool(mdl);
	return;
}

PVOID64 Get_NtProtectVirtualMemory()
{
	//获取方法地址
	unsigned char ida_chars[] =
	{
	  0x40, 0x53, 0x56, 0x57, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56,
	  0x41, 0x57,
	  0x48, 0x81, 0xEC, 0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x8B, 0x05,
	  0xcc, 0xcc, 0xcc, 0xcc, 0x48, 0x33, 0xC4, 0x48, 0x89, 0x84,
	  0x24, 0xcc, 0xcc, 0xcc, 0xcc, 0x45, 0x8B, 0xE1, 0x4C, 0x89,
	  0x44, 0x24, 0xcc, 0x4C, 0x8B, 0xFA, 0x4C, 0x8B, 0xD1, 0x4C,
	  0x8B, 0x8C, 0x24, 0xcc, 0xcc, 0xcc, 0xcc, 0x4C, 0x89, 0x4C,
	  0x24, 0xcc, 0x0F, 0x57, 0xC0, 0x0F, 0x11, 0x44, 0x24, 0xcc,
	  0x0F, 0x11, 0x84, 0x24, 0xcc, 0xcc, 0xcc, 0xcc, 0x0F, 0x11,
	  0x84, 0x24, 0xcc, 0xcc, 0xcc, 0xcc, 0x33, 0xF6, 0x48, 0x89,
	  0x74, 0x24, 0xcc, 0x48, 0x89, 0x74, 0x24, 0xcc, 0x48, 0x89,
	  0x74, 0x24, 0xcc, 0x89, 0x74, 0x24, 0xcc, 0x41, 0x81, 0xFC,
	};
	char moduleName[] = "ntoskrnl.exe";
	char sectionName[] = "PAGE";
	PVOID funAddr = SearchCode(moduleName, sectionName, ida_chars, sizeof(ida_chars));
	if (!MmIsAddressValid(funAddr)) {

		return NULL;
	}
	return funAddr;
}
