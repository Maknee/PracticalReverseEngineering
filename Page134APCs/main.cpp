#include "helper.h"

#include <ntifs.h>
#include <wdm.h>

/*
1) Write a driver using both kernel-mode and user-mode APCs.

//http://www.drdobbs.com/inside-nts-asynchronous-procedure-call/184416590

From this explanation, you can easily realize that APC objects missing a valid NormalRoutine are considered as kernel APCs. Specifically, they are considered as special kernel-mode

In general, every APC object must contain a valid KernelRoutine function pointer, whatever its kind. This driver-defined routine will be the first one to run when the APC is successfully delivered and executed by the NT's APC dispatcher.
User-mode APCs must also contain a valid NormalRoutine function pointer, which must reside in user memory.

Conversely, APC objects that define a valid NormalRoutine are considered regular kernel-mode APCs, given that ApcMode is KernelMode; otherwise, they are considered user-mode APCs. The prototypes for KernelRoutine, RundownRoutine, and NormalRoutine are defined in NTDDK.H as shown in Listing 3.

2) Write a driver that enumerates all user-mode and kernel-mode APCs for
all threads in a process. Hint: You need to take into consideration IRQL
level when performing the enumeration.

3) The kernel function KeSuspendThread is responsible for suspending a
thread. Earlier you learned that APCs are involved in thread suspension
in Windows 8. Explain how this function works and how APCs are used
to implement the functionality on Windows 7. What is different from
Windows 8?

Not explaining both, but rather Windows 10

-> Raise to DPC
-> KiSuspendThread
-> Lock KTHREAD.ThreadLock
-> Check SuspendEvent.Header.SignalState
-> Insert APC [KiInsertQueueApc(&v5->Tcb.648);]

4) APCs are also used in process shutdown. The KTHREAD object has a flag
called ApcQueueable that determines whether an APC may be queued to it.
What happens when you disable APC queueing for a thread? Experiment
with this by starting up notepad.exe and then manually disable APC
queueing to one of its threads (use the kernel debugger to do this).

kd> !process 0 f notepad.exe

PROCESS ffff9f82ad8d9080
    SessionId: 1  Cid: 17a8    Peb: d3e1c54000  ParentCid: 1054
    DirBase: 1ead00002  ObjectTable: ffff89070d51fa00  HandleCount: 249.
    Image: notepad.exe
    VadRoot ffff9f828cacae10 Vads 101 Clone 0 Private 585. Modified 4. Locked 0.
    DeviceMap ffff8907086b3d80
    Token                             ffff8907053d15d0
    ElapsedTime                       00:05:25.014
    UserTime                          00:00:00.000
    KernelTime                        00:00:00.000
    QuotaPoolUsage[PagedPool]         263176
    QuotaPoolUsage[NonPagedPool]      14256
    Working Set Sizes (now,min,max)  (3958, 50, 345) (15832KB, 200KB, 1380KB)
    PeakWorkingSetSize                3860
    VirtualSize                       2101419 Mb
    PeakVirtualSize                   2101423 Mb
    PageFaultCount                    4007
    MemoryPriority                    BACKGROUND
    BasePriority                      8
    CommitCharge                      722

        THREAD ffff9f828a0dd080  Cid 17a8.12c0  Teb: 000000d3e1c55000 Win32Thread: ffff9f82861b5e20 WAIT: (WrUserRequest) UserMode Non-Alertable
            ffff9f828caa10c0  QueueObject


kd> .process /i /r ffff9f82ad8d9080

kd> dtx _KTHREAD ffff9f82ad8d9080
    [+0x074 (14:14)] ApcQueueable     : 0x0 [Type: unsigned long]

kd> ? 0xffff9f82ad8d9080 + 0x74
Evaluate expression: -106091370409740 = ffff9f82`ad8d90f4

//fifteenth bit, so... make it 0

eb ffff9f82`8cddf0f5 0

5) Explain what the following functions do:
■ KiInsertQueueApc
■ PsExitSpecialApc
■ PspExitApcRundown
■ PspExitNormalApc
■ PspQueueApcSpecialApc
■ KiDeliverApc

First block:
dt nt!_KAPC
+0x010 ApcListEntry     : _LIST_ENTRY

PKTHREAD thread = Apc->Thread
if(!Apc->ApcStateIndex) {
  goto 1400F3815
} else {
  goto 1400F3822
}

1400F3815:
if(thread->ApcStateIndex) {
  goto 1400F38DF eax = 0x258 (goes to 1400F3830)
} else {
  goto 1400F3822
}

1400F3822:
Apc->ApcStateIndex = thread->ApcStateIndex
eax = 0x98

1400F3830:

dt nt!_KTHREAD
+0x098 ApcState         : _KAPC_STATE
+0x258 SavedApcState    : _KAPC_STATE

dt nt!_KAPC
+0x051 ApcMode          : Char

dt nt!_KAPC_STATE
+0x030 NormalRoutine    : Ptr64     void

r8 = thread->ApcState or thread->SavedApcState
al = Apc->ApcMode
if(Apc->NormalRoutine) {
  goto 1400F383D
} else {
  goto 1400F38AB
}

6. Explain how the function KeEnumerateQueueApc works and then recover
its prototype. Note: This function is available only on Windows 8.

Not avaliable on Windows 10

7) Explain how the kernel dispatches APCs. Write a driver that uses the different kinds of APCs and view the stack when they are executed.
Note: We used the same method to figure out how the kernel dispatches work items.

*/

extern "C" {
  NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath);
}

typedef VOID(*PKRUNDOWN_ROUTINE)(
  PKAPC Apc
  );

typedef VOID(*PKNORMAL_ROUTINE)(
  PVOID NormalContext,
  PVOID SystemArgument1,
  PVOID SystemArgument2
  );

typedef VOID(*PKKERNEL_ROUTINE)(
  PKAPC Apc,
  PKNORMAL_ROUTINE *NormalRoutine,
  PVOID *NormalContext,
  PVOID *SystemArgument1,
  PVOID *SystemArgument2
  );

typedef enum _KAPC_ENVIRONMENT {
  OriginalApcEnvironment,
  AttachedApcEnvironment,
  CurrentApcEnvironment,
  InsertApcEnvironment
} KAPC_ENVIRONMENT, *PKAPC_ENVIRONMENT;

using PKeInitializeApc = NTKERNELAPI VOID(*)(
  PKAPC Apc,
  PKTHREAD Thread,
  KAPC_ENVIRONMENT Environment,
  PKKERNEL_ROUTINE KernelRoutine,
  PKRUNDOWN_ROUTINE RundownRoutine,
  PKNORMAL_ROUTINE NormalRoutine,
  KPROCESSOR_MODE ProcessorMode,
  PVOID NormalContext
  );

using PKeInsertQueueApc = NTKERNELAPI BOOLEAN(*)(
  PRKAPC Apc,
  PVOID SystemArgument1,
  PVOID SystemArgument2,
  KPRIORITY Increment
  );

using PKeTestAlertThread = NTKERNELAPI VOID(*)(
  KPROCESSOR_MODE AlertMode
  );

UNICODE_STRING KeInitializeApcString = RTL_CONSTANT_STRING(L"KeInitializeApc");
UNICODE_STRING KeInsertQueueApcString = RTL_CONSTANT_STRING(L"KeInsertQueueApc");
UNICODE_STRING KeTestAlertThreadString = RTL_CONSTANT_STRING(L"KeTestAlertThread");

void KernelApcRoutine(PKAPC Apc, PKNORMAL_ROUTINE *NormalRoutine, PVOID *NormalContext, PVOID *SystemArgument1, PVOID *SystemArgument2)
{
  UNREFERENCED_PARAMETER(Apc);
  UNREFERENCED_PARAMETER(NormalRoutine);
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  PrintFunction();

  KIRQL irql = KeGetCurrentIrql();
  Print("Executing kernel APC at IRQL: %d\n", irql);

  //Set to alertable
  PKeTestAlertThread KeTestAlertThread = (PKeTestAlertThread)MmGetSystemRoutineAddress(&KeTestAlertThreadString);
  if (KeTestAlertThread) {
    KeTestAlertThread(UserMode);
  }

  ExFreePool(Apc);
}

void UserApcRoutine(PVOID NormalContext, PVOID SystemArgument1, PVOID SystemArgument2) {
  UNREFERENCED_PARAMETER(NormalContext);
  UNREFERENCED_PARAMETER(SystemArgument1);
  UNREFERENCED_PARAMETER(SystemArgument2);

  PrintFunction();

  KIRQL irql = KeGetCurrentIrql();
  Print("Executing user APC at IRQL: %d\n", irql);
}

void ApcRundownRoutine(PKAPC apc) {
  ExFreePool(apc);
}

void QueueAPCs() {
  PKeInitializeApc KeInitializeApc = (PKeInitializeApc)MmGetSystemRoutineAddress(&KeInitializeApcString);
  if (!KeInitializeApc) {
    Print("Failed to fetch KeInitializeApc!\n");
    return;
  }

  PKeInsertQueueApc KeInsertQueueApc = (PKeInsertQueueApc)MmGetSystemRoutineAddress(&KeInsertQueueApcString);
  if (!KeInsertQueueApc) {
    Print("Failed to fetch KeInsertQueueApc!\n");
    return;
  }

  PETHREAD current_thread = PsGetCurrentThread();

  //TODO
  /*
  PKAPC user_apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
  KeInitializeApc(user_apc, current_thread, OriginalApcEnvironment, KernelApcRoutine, ApcRundownRoutine, UserApcRoutine, UserMode, NULL);
  KeInsertQueueApc(user_apc, NULL, NULL, 0);
  */

  //passive level kernel apc
  PKAPC kernel_apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
  KeInitializeApc(kernel_apc, current_thread, OriginalApcEnvironment, KernelApcRoutine, NULL, UserApcRoutine, KernelMode, NULL);
  KeInsertQueueApc(kernel_apc, NULL, NULL, 0);

  //executed right after queued
  PKAPC special_kernel_apc = (PKAPC)ExAllocatePool(NonPagedPool, sizeof(KAPC));
  KeInitializeApc(special_kernel_apc, current_thread, OriginalApcEnvironment, KernelApcRoutine, NULL, NULL, KernelMode, NULL);
  KeInsertQueueApc(special_kernel_apc, NULL, NULL, 0);
}

void EnumerateApcs(HANDLE pid) {
  PEPROCESS process{};
  if (!NT_SUCCESS(PsLookupProcessByProcessId(pid, &process))) {
    //If pid wasn't found, then use the current process
    process = PsGetCurrentProcess();
  }

  //+0x098 ApcState         : _KAPC_STATE

  //nt!_KAPC_STATE
  //  + 0x000 ApcListHead      : [2] _LIST_ENTRY

  /*
  nt!_KAPC
   +0x000 Type             : UChar
   +0x001 SpareByte0       : UChar
   +0x002 Size             : UChar
   +0x003 SpareByte1       : UChar
   +0x004 SpareLong0       : Uint4B
   +0x008 Thread           : Ptr64 _KTHREAD
   +0x010 ApcListEntry     : _LIST_ENTRY
  */
  LIST_ENTRY* KernelApcListHead = (LIST_ENTRY*)(((PCHAR)(process)) + 0x98);
  LIST_ENTRY* UserApcListHead = KernelApcListHead + 1;

  Print("Kernel APCs:\n");

  for (LIST_ENTRY* entry = KernelApcListHead->Blink; entry != NULL && entry != KernelApcListHead; entry = entry->Blink) {
    PKAPC apc = (PKAPC)(((PCHAR)(entry)) - 0x10);
    Print("Kernel APC: %p\n", apc);
  }

  Print("User APCs:\n");

  for (LIST_ENTRY* entry = UserApcListHead->Blink; entry != NULL && entry != UserApcListHead; entry = entry->Blink) {
    PKAPC apc = (PKAPC)(((PCHAR)(entry)) - 0x10);
    Print("User APC: %p\n", apc);
  }
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
#define IOCTL_QUEUE_APCS                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_CREATE_SYSTEM_ENUM_APCS                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

// IOCTL handler
NTSTATUS DriverIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);
  PrintFunction();

  PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);

  switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_QUEUE_APCS:
    QueueAPCs();
    break;
  case IOCTL_CREATE_SYSTEM_ENUM_APCS:
    int* pid = (int*)Irp->AssociatedIrp.SystemBuffer;
    ULONG input_length = irp_stack->Parameters.DeviceIoControl.InputBufferLength;
    if (input_length == sizeof(int)) {
      EnumerateApcs((HANDLE)(*pid));
    }
    else {
      //enumerate system process
      EnumerateApcs((HANDLE)4);
    }
    break;
  }

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

// Device names
WCHAR w_device_name[] = L"\\Device\\Page134APCs";
WCHAR w_dos_device_name[] = L"\\DosDevices\\Page134APCs";

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