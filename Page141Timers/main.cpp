#include "helper.h"

#include <ntifs.h>
#include <wdm.h>

/*

*/


extern "C" {
  NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);
}

void DummyDPC(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);
  
  Print("Processor [%d] - Dummy Dpc - Routine: %p\n", KeGetCurrentProcessorNumber(), Dpc->DeferredRoutine);
}

void EnumerateDPCs(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(Dpc);
  UNREFERENCED_PARAMETER(DeferredContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  //this is one way via PCR
  PKPCR pcr = KeGetPcr();
  PCHAR prcb = (PCHAR)pcr->CurrentPrcb;

  //nt!_KPRCB
  //+0x2e00 DpcData          : [2] _KDPC_DATA

  PCHAR DpcData = prcb + 0x2e00;

  //nt!_KDPC_DATA
  //+ 0x000 DpcList          : _KDPC_LIST

  //nt!_KDPC_LIST
  //+ 0x000 ListHead         : _SINGLE_LIST_ENTRY
  //+ 0x008 LastEntry : Ptr64 _SINGLE_LIST_ENTRY

  //?? sizeof(_KDPC_DATA)
  //unsigned int64 0x28

  constexpr size_t KDPC_DATA_SIZE = 0x28;

  SINGLE_LIST_ENTRY* NormalDpcList = (SINGLE_LIST_ENTRY*)(DpcData);
  SINGLE_LIST_ENTRY* ThreadedDpcList = (SINGLE_LIST_ENTRY*)(DpcData + KDPC_DATA_SIZE);

  Print("Processor [%d] DPCs:\n", KeGetCurrentProcessorNumber());

  for (SINGLE_LIST_ENTRY* entry = NormalDpcList->Next; entry != NULL && entry != NormalDpcList; entry = entry->Next) {
    /*
    nt!_KDPC
      + 0x000 TargetInfoAsUlong : Uint4B
      + 0x000 Type : UChar
      + 0x001 Importance : UChar
      + 0x002 Number : Uint2B
      + 0x008 DpcListEntry : _SINGLE_LIST_ENTRY
      + 0x010 ProcessorHistory : Uint8B
      + 0x018 DeferredRoutine : Ptr64     void
      + 0x020 DeferredContext : Ptr64 Void
      + 0x028 SystemArgument1 : Ptr64 Void
      + 0x030 SystemArgument2 : Ptr64 Void
      + 0x038 DpcData : Ptr64 Void
    */
    PKDPC dpc = (PKDPC)(((PCHAR)(entry)) - 0x8);
    Print("Normal DPC: %p - Routine: %p\n", dpc, dpc->DeferredRoutine);
  }

  for (SINGLE_LIST_ENTRY* entry = ThreadedDpcList->Next; entry != NULL && entry != ThreadedDpcList; entry = entry->Next) {
    PKDPC dpc = (PKDPC)(((PCHAR)(entry)) - 0x8);
    Print("Threaded DPC: %p - Routine: %p\n", dpc, dpc->DeferredRoutine);
  }

  //Another way via just iterating dpcs (only one list) by walking dpc list
  //This assumes that this enumerate dpc is the head of the singlely linked dpc list.
  for (SINGLE_LIST_ENTRY* entry = Dpc->DpcListEntry.Next; entry != NULL && entry != &Dpc->DpcListEntry; entry = entry->Next) {
    PKDPC dpc = (PKDPC)(((PCHAR)(entry)) - 0x8);
    Print("Another iteration of normal DPC: %p - Routine: %p\n", dpc, dpc->DeferredRoutine);
  }
}

void ScheduleEnumerateDpcs() {
  //initialize dpc for each processor to enumerate dpcs
  PKDPC dpc = (PKDPC)ExAllocatePool(NonPagedPool, sizeof(KDPC) * KeNumberProcessors * 2);
  
  //raise irql to dpc because this processor might be interrupted to service dpc
  //be better to sync using:
  //technique used in (Page 275) The Rootkit Arsenal: Escape and Evasion in the Dark Corners of the System Second Edition
  //which executes a function on all processors at DPC level

  KIRQL old_irql = KeRaiseIrqlToDpcLevel();

  //queue enumeration first and then dummy dpc for each processor

  for (CCHAR i = 0; i < KeNumberProcessors; i++) {
    KeInitializeDpc(&dpc[i], EnumerateDPCs, NULL);
    KeSetTargetProcessorDpc(&dpc[i], i);
    KeInsertQueueDpc(&dpc[i], NULL, NULL);

    int dummy_dpc_index = KeNumberProcessors + i;
    KeInitializeDpc(&dpc[dummy_dpc_index], DummyDPC, NULL);
    KeSetTargetProcessorDpc(&dpc[dummy_dpc_index], i);
    KeInsertQueueDpc(&dpc[dummy_dpc_index], NULL, NULL);
  }

  KeLowerIrql(old_irql);

  ExFreePool(dpc);
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);
  PrintFunction();

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

// IOCTLs
#define IOCTL_ENUMERATE_DPCS                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

// IOCTL handler
NTSTATUS DriverIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);
  PrintFunction();

  PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);

  switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_ENUMERATE_DPCS:
    ScheduleEnumerateDpcs();
    break;
  }

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

// Device names
WCHAR w_device_name[] = L"\\Device\\Page140DPCs";
WCHAR w_dos_device_name[] = L"\\DosDevices\\Page140DPCs";

void DriverUnload(PDRIVER_OBJECT DriverObject) {
  PrintFunction();

  UNICODE_STRING dos_device_name{};
  RtlInitUnicodeString(&dos_device_name, w_dos_device_name);

  IoDeleteSymbolicLink(&dos_device_name);

  IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject,
  PUNICODE_STRING RegistryPath) {

  UNREFERENCED_PARAMETER(RegistryPath);
  PrintFunction();

  NTSTATUS status;

  // Create a device
  UNICODE_STRING device_name{};
  RtlInitUnicodeString(&device_name, w_device_name);

  PDEVICE_OBJECT device_object{};
  if (!NT_SUCCESS(status = IoCreateDevice(
    DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
    FILE_DEVICE_SECURE_OPEN, FALSE, &device_object))) {
    DbgPrintLine("Couldn't create device");
    return status;
  }

  // Create a symlink to device
  UNICODE_STRING dos_device_name{};
  RtlInitUnicodeString(&dos_device_name, w_dos_device_name);

  if (!NT_SUCCESS(status =
    IoCreateSymbolicLink(&dos_device_name, &device_name))) {
    DbgPrintLine("Couldn't create symbolic link");
    IoDeleteDevice(device_object);
    return status;
  }

  // Setup driver handlers
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctl;
  DriverObject->DriverUnload = DriverUnload;

  return STATUS_SUCCESS;
}