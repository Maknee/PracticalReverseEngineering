#include "helper.h"

#include <ntifs.h>
#include <wdm.h>

/*
1) Where and when is the DpcData field in KPRCB initialized?

In Practical Reverse Engineering, it mentions KiStartDpcThread, which runs through each dpc queue, so I started there.

It looks it executes the thread, so the DpcData must be initialized before. XRefs to KiStartDpcThread gives:
KiInitializeDynamicProcessor
KeInitSystem

Let's check KeInitSystem. We get something like:

      KiInitializeProcessor(*v8);
      if ( KeThreadDpcEnable )
      {
        if ( (signed int)KiStartDpcThread((__int64)v9) < 0 )
          return 0;
      }
      ++v7;
      ++v8;

KiInitializeProcessor should be interesting as Dpcs, as we know, are associated with processors.

Ah ha!

__int64 __fastcall KiInitializeProcessor(_KPRCB *a1)
{
  _KPRCB *v1; // rdi
  __int16 v2; // cx
  unsigned __int64 v3; // rax
  unsigned __int64 v4; // rax
  void **v5; // rax
  size_t v6; // r8
  unsigned __int64 v7; // r8
  unsigned __int64 v8; // rax
  unsigned __int64 v9; // rax

  v1 = a1;
  if ( KeThreadDpcEnable )
  {
    KeInitializeGate(&a1->DpcGate);
    KiInitializeDpcList(&v1->DpcData[1].DpcList.ListHead.Next);

KiInitializeDpcList seems like a hit :)

void __fastcall KiInitializeDpcList(_QWORD *a1)
{
  *a1 = 0i64;
  a1[1] = a1;
}

It is initialized to NULL

2) Write a driver to enumerate all DPCs on the entire system. Make sure
you support multi-processor systems! Explain the difficulties and how
you solved them.

Page140DPCs: Processor [0] DPCs:
Page140DPCs: Normal DPC: FFFF9F8283D020D0 - Routine: FFFFF8053EBF1150
Page140DPCs: Another iteration of normal DPC: FFFF9F8283D020D0 - Routine: FFFFF8053EBF1150
Page140DPCs: Processor [0] - Dummy Dpc - Routine: FFFFF8053EBF1150
Page140DPCs: Processor [1] DPCs:
Page140DPCs: Normal DPC: FFFF9F8283D02110 - Routine: FFFFF8053EBF1150
Page140DPCs: Another iteration of normal DPC: FFFF9F8283D02110 - Routine: FFFFF8053EBF1150
Page140DPCs: Processor [1] - Dummy Dpc - Routine: FFFFF8053EBF1150
Page140DPCs: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)

This isn't still a perfect solution, but it's pretty close (I think).
Dpcs are associated with each processor, so the first thing I realized was that I had to figure out how to queue them
for each processor. I found that you can set the dpc's targeted processor using KeSetTargetProcessorDpc().
Then, I had a dumb issue where I didn't allocate the DPC in the nonpaged pool (it was on the stack...) and the dpc handler/executer/watchdog/whatever accessed it - Oof, paged out.
I wasn't getting any result from queuing the DPC, so I made a dummy dpc.
This still wasn't giving any results. Why? Because I inserted the DPC at PASSIVE_LEVEL, which could be interrupted to service the DPCs.
This is why I wasn't seeing the dummy dpc.
So, I had to raise the irql of the current processor to DPC level.
Still, this doesn't increase the irql of the other processor and I didn't feel like implementing it.
(This can be done by synchronzing processors using locks + irql increment + KeSetThreadAffinity/ZwSetThreadInformation)
Still reliable? It prints out the dummy dpc and sometimes other dpcs by chance.
(Maybe better solution is to spin the processor for x time and gather all the DPCs, haha)


3) Explain how the KiDpcWatchdog routine works.

.text:0000000140110170 ; void __stdcall KiDpcWatchdog(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2)
.text:0000000140110170 KiDpcWatchdog proc near
.text:0000000140110170 sub     rsp, 28h
.text:0000000140110174 mov     rcx, gs:20h     ; KeGetCurrentPrcb()
.text:000000014011017D cli                     ; Disable interrupts
.text:000000014011017E and     dword ptr [rcx+58ECh], 0 ; Dpc->DpcWatchdogCount = 0
.text:0000000140110185 call    KiResetGlobalDpcWatchdogProfiler ; (Prcb)
.text:000000014011018A sti                     ; Enable Interrupts
.text:000000014011018B add     rsp, 28h
.text:000000014011018F retn
.text:000000014011018F KiDpcWatchdog 

Basically only sets DpcWatchdogCount to zero... Other than that, it does nothing basically.

void KiDpcWatchdog(struct _KDPC *Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
  struct KPRCB* prcb = KeGetCurrentPrcb();
  __asm__ {"cli"}
  Dpc->DpcWatchdogCount = 0;
  KiResetGlobalDpcWatchdogProfiler(prcb);
  __asm__ {"sti"}
}

A look at KiResetGlobalDpcWatchdogProfiler.

.text:0000000140110198                 sub     rsp, 28h
.text:000000014011019C                 mov     r9, [rcx+61A8h] ; Dpc->DpcWatchDogProfile
.text:00000001401101A3                 test    r9, r9
.text:00000001401101A6                 jz      short loc_1401101B5 ; Dpc->DpcWatchDogProfile != NULL
.text:00000001401101A8                 cmp     [rcx+61B0h], r9 ; Dpc->DpcWatchdogProfileCurrentEmptyCapture == Dpc->DpcWatchDogProfile
.text:00000001401101AF                 jnz     loc_1401FD69E
.text:00000001401101B5
.text:00000001401101B5 loc_1401101B5:                          ; CODE XREF: KiResetGlobalDpcWatchdogProfiler+E↑j
.text:00000001401101B5                                         ; KiResetGlobalDpcWatchdogProfiler+ED512↓j ...
.text:00000001401101B5                 add     rsp, 28h
.text:00000001401101B9                 retn

.text:00000001401FD69E loc_1401FD69E:                          ; CODE XREF: KiResetGlobalDpcWatchdogProfiler+17↑j
.text:00000001401FD69E                                         ; DATA XREF: .pdata:000000014040C3C0↓o ...
.text:00000001401FD69E                 mov     eax, [rcx+58F4h] ; eax = Dpc->DpcWatchdogProfileCumulativeDpcThreshold
.text:00000001401FD6A4                 cmp     [rcx+58ECh], eax ; Dpc->WatchDogCount >= Dpc->DpcWatchdogProfileCumulativeDpcThreshold
.text:00000001401FD6AA                 jge     loc_1401101B5
.text:00000001401FD6B0                 mov     r8d, cs:KiDpcWatchdogProfileArrayLength
.text:00000001401FD6B7                 xor     edx, edx        ; Val
.text:00000001401FD6B9                 mov     [rcx+61B0h], r9 ; Dpc->DpcWatchdogProfileCurrentEmptyCapture = Dpc->DpcWatchDogProfile
.text:00000001401FD6C0                 mov     rcx, r9         ; Dst
.text:00000001401FD6C3                 shl     r8, 3           ; Size
.text:00000001401FD6C7                 call    memset          ; (Dpc->DpcWatchDogProfile, 0, KiDpcWatchdogProfileArrayLength * 8)
.text:00000001401FD6CC                 nop
.text:00000001401FD6CD                 jmp     loc_1401101B5

void KiResetGlobalDpcWatchdogProfiler(struct KPRCB* prcb) {
  if(!Dpc->DpcWatchDogProfile) {
    if(Dpc->DpcWatchdogProfileCurrentEmptyCapture == Dpc->DpcWatchDogProfile) {
      if(Dpc->WatchDogCount >= Dpc->DpcWatchdogProfileCumulativeDpcThreshold) {
        Dpc->DpcWatchdogProfileCurrentEmptyCapture = Dpc->DpcWatchDogProfile;
        memset(Dpc->DpcWatchDogProfile, 0, KiDpcWatchdogProfileArrayLength * 8);
      }
    }
  }
}

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