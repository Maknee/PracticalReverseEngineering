#include "helper.h"

#include <ntifs.h>
#include <ntddk.h>

/*
1)
After reading some online forums, you notice some people suggesting that
PsCreateSystemThread will create a thread in the context of the calling process.
In other words, they are suggesting that if you call PsCreateSystemThread in an
IOCTL handler, the new thread will be in the context of the requesting user-mode
application. Assess the validity of this statement by writing a driver that
calls PsCreateSystemThread in the IOCTL handler. Next, experiment with a
non-NULL ProcessHandle and determine if the context differs.

PsCreateSystemThread
https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/wdm/nf-wdm-pscreatesystemthread

ProcessHandle

Specifies an open handle for the process in whose address space the thread is to be run.
The caller's thread must have PROCESS_CREATE_THREAD access to this process.
If this parameter is not supplied, the thread will be created in the initial system process.
This value should be NULL for a driver-created thread.
Use the NtCurrentProcess macro, defined in Ntddk.h, to specify the current process.

Output from running the driver:
1: kd> g
Page128SystemThreads: long __cdecl DriverEntry(struct _DRIVER_OBJECT *,struct _UNICODE_STRING *)
Page128SystemThreads: PID 0000000000000004

Page128SystemThreads: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)
Page128SystemThreads: long __cdecl DriverIoctl(struct _DEVICE_OBJECT *,struct _IRP *)
Page128SystemThreads: void *__cdecl CreateContextPsCreateSystemThreadProcessHandleNull(void (__cdecl *)(void *))
Page128SystemThreads: PID 0000000000000580

Page128SystemThreads: void __cdecl SomeThread(void *)
Page128SystemThreads: PID 0000000000000004

Page128SystemThreads: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)
Page128SystemThreads: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)
Page128SystemThreads: long __cdecl DriverIoctl(struct _DEVICE_OBJECT *,struct _IRP *)
Page128SystemThreads: void *__cdecl CreateContextPsCreateSystemThreadProcessHandle(void (__cdecl *)(void *))
Page128SystemThreads: PID 0000000000000F14

Page128SystemThreads: void __cdecl SomeThread(void *)
Page128SystemThreads: PID 0000000000000F14

Page128SystemThreads: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)

Run from debugged vm:
Running PsCreateSystemThread with null process handle:
Z:\SharedVMFolder>python Page128SystemThreads.py 0
IOCTL success!

Running PsCreateSystemThread with current process handle from context of ioctl:
Z:\SharedVMFolder>python Page128SystemThreads.py 1
IOCTL success!

Explained:
Page128SystemThreads: void *__cdecl CreateContextPsCreateSystemThreadProcessHandleNull(void (__cdecl *)(void *))
Page128SystemThreads: PID 0000000000000580

Page128SystemThreads: void __cdecl SomeThread(void *)
Page128SystemThreads: PID 0000000000000004

PID of 580 is the pid of the current process running the ioctl handler while 4 is the PID of the System process. 
This makes sense as the system process should handle running the thread

Page128SystemThreads: void *__cdecl
CreateContextPsCreateSystemThreadProcessHandle(void (__cdecl *)(void *))
Page128SystemThreads: PID 0000000000000F14

Page128SystemThreads: void __cdecl SomeThread(void *)
Page128SystemThreads: PID 0000000000000F14

Both PIDs are the same, which means that if we pass a process handle to PsCreateSystemThread, it will execute
the thread in the current process

2)
Cross-reference as many calls to PsCreateSystemThread as possible in
the kernel image. Determine whether any of them pass a non-NULL
ProcessHandle parameter. Explain the purpose of these routines. Repeat
the exercise for as many functions as possible

SmKmStoreHelperStart proc near

.text:00000001400DCD9C mov     r11, rsp
.text:00000001400DCD9F mov     [r11+8], rbx
.text:00000001400DCDA3 push    rdi
.text:00000001400DCDA4 sub     rsp, 40h
.text:00000001400DCDA8 mov     [r11-18h], rcx
.text:00000001400DCDAC lea     rax, SmKmStoreHelperWorker
.text:00000001400DCDB3 mov     rdi, rcx
.text:00000001400DCDB6 mov     [r11-20h], rax
.text:00000001400DCDBA and     qword ptr [r11-28h], 0
.text:00000001400DCDBF lea     rcx, [r11+18h]  ; ThreadHandle
.text:00000001400DCDC3 mov     r9, rdx         ; ProcessHandle = rdx (second
argument) .text:00000001400DCDC6 xor     r8d, r8d        ; ObjectAttributes
.text:00000001400DCDC9 mov     edx, 1FFFFFh    ; DesiredAccess
.text:00000001400DCDCE call    PsCreateSystemThread

The Process Handle is based on what is passed in to rdx (second argument of this function)

public: static long SMKM_STORE<struct SM_TRAITS>::SmStWorkerThreadStartThread(struct SMKM_STORE<struct SM_TRAITS> *, void *, void (*)(void *), struct _ETHREAD * *)

...
.text:00000001400DCE42 mov     rsi, rdx        ; rsi = 2nd arg
.text:00000001400DCE45 xor     edx, edx        ; Val
.text:00000001400DCE47 mov     rdi, r8
.text:00000001400DCE4A mov     rbx, rcx
.text:00000001400DCE4D mov     r14, r9
.text:00000001400DCE50 lea     rcx, [rbp+Dst]  ; Dst
.text:00000001400DCE54 lea     r8d, [rdx+28h]  ; Size
.text:00000001400DCE58 call    memset
.text:00000001400DCE5D and     [rbp+var_20], 0
.text:00000001400DCE62 lea     rax, [rbp+var_18]
.text:00000001400DCE66 and     [rbp+var_1C], 0
.text:00000001400DCE6A lea     rcx, [rbp+ThreadHandle] ; ThreadHandle
.text:00000001400DCE6E or      [rbp+var_8], 0FFFFFFFFh
.text:00000001400DCE72 mov     r9, rsi         ; ProcessHandle = second arg (from rsi)

Again, process handle is based on the second argument of the function

.text:000000014013AABC ; public: static long SMKM_STORE_MGR<struct SM_TRAITS>::SmCompressCtxCreateThread(struct SMKM_STORE_MGR<struct SM_TRAITS>::_SM_COMPRESS_CONTEXT *, struct SMKM_STORE_MGR<struct SM_TRAITS> *, unsigned long) .text:000000014013AABC
?SmCompressCtxCreateThread@?$SMKM_STORE_MGR@USM_TRAITS@@@@SAJPEAU_SM_COMPRESS_CONTEXT@1@PEAU1@K@Z

.text:000000014013AABC mov     [rsp-8+arg_0], rbx
.text:000000014013AAC1 mov     [rsp-8+arg_8], rsi
.text:000000014013AAC6 mov     [rsp-8+arg_10], rdi
.text:000000014013AACB push    rbp
.text:000000014013AACC mov     rbp, rsp
.text:000000014013AACF sub     rsp, 60h
.text:000000014013AAD3 and     [rbp+ThreadHandle], 0
.text:000000014013AAD8 mov     rdi, rdx        ; struct SMKM_STORE_MGR<struct SM_TRAITS>* holds process handle
...
.text:000000014013AB2A loc_14013AB2A:          ; ProcessHandle = SMKM_STORE_MGR + 0x740
.text:000000014013AB2A mov     r9, [rdi+740h]
.text:000000014013AB31 lea     rcx, [rbp+ThreadHandle] ; ThreadHandle	
.text:000000014013AB35 mov     [rsp+60h+StartContext], rbx ; StartContext
.text:000000014013AB3A xor     r8d, r8d        ; ObjectAttributes
.text:000000014013AB3D mov     [rsp+60h+StartRoutine], rax ; StartRoutine
.text:000000014013AB42 mov     edx, 1FFFFFh    ; DesiredAccess
.text:000000014013AB47 and     [rsp+60h+var_40], 0
.text:000000014013AB4D call    PsCreateSystemThread

Process handle = SMKM_STORE_MGR + 0x740

.text:000000014016C37C PopCreatePowerThread proc near

.text:000000014016C37C mov     rax, rsp
.text:000000014016C37F push    rbx
.text:000000014016C380 sub     rsp, 70h
.text:000000014016C384 and     qword ptr [rax-30h], 0
.text:000000014016C389 lea     r8, [rax-38h]   ; ObjectAttributes
.text:000000014016C38D and     qword ptr [rax-28h], 0
.text:000000014016C392 xorps   xmm0, xmm0
.text:000000014016C395 mov     [rax-48h], rdx
.text:000000014016C399 mov     ebx, 1FFFFFh
.text:000000014016C39E mov     [rax-50h], rcx
.text:000000014016C3A2 mov     edx, ebx        ; DesiredAccess
.text:000000014016C3A4 and     qword ptr [rax-58h], 0
.text:000000014016C3A9 lea     rcx, [rax+18h]  ; ThreadHandle
.text:000000014016C3AD xor     r9d, r9d        ; ProcessHandle (In this case, it is NULL, which means to execute as thread under system)
.text:000000014016C3B0 mov     dword ptr [rax-38h], 30h
.text:000000014016C3B7 mov     dword ptr [rax-20h], 200h
.text:000000014016C3BE movdqu  xmmword ptr [rax-18h], xmm0
.text:000000014016C3C3 call    PsCreateSystemThread

System thread

.text:000000014017B33C ; __int64 __fastcall CcInitializePartition(PVOID StartContext)
.text:000000014017B33C CcInitializePartition proc near

...
.text:000000014017B359 mov     rbp, rdx   ; ProcessHandle = second arg
...
.text:000000014017B6F0 mov     r9, [rbp+70h]   ; ProcessHandle = second arg + 0x70
.text:000000014017B6F4 mov     [rsp+88h+StartRoutine], rax ; StartRoutine
.text:000000014017B6F9 mov     [rsp+88h+ClientId], rsi ; ClientId
.text:000000014017B6FE movdqu  xmmword ptr [rsp+88h+ObjectAttributes.SecurityDescriptor], xmm0
.text:000000014017B704 call    PsCreateSystemThread

.text:000000014017B8A4 CcInitializeAsyncRead proc near

...
.text:000000014017B8C2 mov     rsi, rcx        ; first arg
...
.text:000000014017BBB8 loc_14017BBB8:          ; rax = first arg + 0x8
.text:000000014017BBB8 mov     rax, [rsi+8]
.text:000000014017BBBC lea     r8, [rsp+88h+ObjectAttributes] ; ObjectAttributes
.text:000000014017BBC1 mov     [rsp+88h+StartContext], rbx ; StartContext
.text:000000014017BBC6 lea     rcx, [rsp+88h+ThreadHandle] ; ThreadHandle
.text:000000014017BBCE mov     edx, 1FFFFFh    ; DesiredAccess
.text:000000014017BBD3 mov     r9, [rax+70h]   ; ProcessHandle = (*(first arg + 0x8) + 0x70)
.text:000000014017BBD7 lea     rax, CcAsyncReadWorker
.text:000000014017BBDE mov     [rsp+88h+StartRoutine], rax ; StartRoutine
.text:000000014017BBE3 mov     [rsp+88h+ClientId], rdi ; ClientId
.text:000000014017BBE8 call    PsCreateSystemThread
.text:000000014017BBED test    eax, eax
.text:000000014017BBEF js      loc_14021A7

Process handle is located in some struct + 0x70

.text:00000001400D0D8C MiZeroInParallel proc near

.text:00000001401EE9C2 loc_1401EE9C2:
.text:00000001401EE9C2 lea     rax, [rbp+var_40]
.text:00000001401EE9C6 xor     r9d, r9d        ; ProcessHandle = NULL
.text:00000001401EE9C9 mov     [rsp+80h+StartContext], rax ; StartContext
.text:00000001401EE9CE lea     rcx, [rbp+ThreadHandle] ; ThreadHandle
.text:00000001401EE9D2 lea     rax, MiZeroInParallelWorker
.text:00000001401EE9D9 xor     r8d, r8d        ; ObjectAttributes
.text:00000001401EE9DC mov     [rsp+80h+StartRoutine], rax ; StartRoutine
.text:00000001401EE9E1 mov     edx, 1FFFFFh    ; DesiredAccess
.text:00000001401EE9E6 and     [rsp+80h+var_60], 0
.text:00000001401EE9EC call    PsCreateSystemThread
.text:00000001401EE9F1 test    eax, eax

Process handle is null, so StartRoutine is executed as a thread under system process.

Cool. So basically, xor r9 when routines want to execute thread under system process


*/

extern "C" {
NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
                     _In_ PUNICODE_STRING RegistryPath);
}

//Thread spawned by PsCreateSystemThread
void SomeThread(IN PVOID StartContext) {
  UNREFERENCED_PARAMETER(StartContext);
  PrintFunction();

  Print("PID %p\n\n", PsGetCurrentProcessId());
}

//Create a system thread passing in the process handle as NULL
HANDLE
CreateContextPsCreateSystemThreadProcessHandleNull(PKSTART_ROUTINE routine) {
  PrintFunction();
  Print("PID %p\n\n", PsGetCurrentProcessId());

  HANDLE system_thread_handle{};
  NTSTATUS status{};

  HANDLE process_handle = NULL;

  // Create system thread, passing in process handle
  if ((status = PsCreateSystemThread(&system_thread_handle, THREAD_ALL_ACCESS,
                                     NULL, process_handle, NULL, routine,
                                     NULL)) != STATUS_SUCCESS) {
    return NULL;
  }
  return system_thread_handle;
}

// Create a system thread passing in the process handle as the handle to the current process
HANDLE
CreateContextPsCreateSystemThreadProcessHandle(PKSTART_ROUTINE routine) {
  PrintFunction();
  Print("PID %p\n\n", PsGetCurrentProcessId());

  HANDLE system_thread_handle{};
  NTSTATUS status{};

  //Open the current process
  PEPROCESS current_process = PsGetCurrentProcess();
  HANDLE process_handle;

  //Get a handle to current process
  if (!NT_SUCCESS(status = ObOpenObjectByPointer(
                      current_process, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL,
                      NULL, KernelMode, &process_handle))) {
    DbgPrintLine("Failed to open process by pointer");

	return NULL;
  }

  // Create system thread, passing in process handle
  if ((status = PsCreateSystemThread(
           &system_thread_handle, THREAD_ALL_ACCESS | PROCESS_ALL_ACCESS, NULL,
           process_handle, NULL, routine, NULL)) != STATUS_SUCCESS) {
    return NULL;
  }

  //Make sure to clean up references/handles
  ZwClose(process_handle);
  ObDereferenceObject(current_process);

  return system_thread_handle;
}

NTSTATUS DriverCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);
  PrintFunction();

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

//IOCTL for choosing between creating a system thread with process handle of null or of the current process 
#define IOCTL_CREATE_SYSTEM_THREAD_NULL                                        \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_CREATE_SYSTEM_THREAD_HANDLE                                      \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

//IOCTL handler
NTSTATUS DriverIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
  UNREFERENCED_PARAMETER(DeviceObject);
  PrintFunction();

  PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);

  switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
  case IOCTL_CREATE_SYSTEM_THREAD_NULL:
    CreateContextPsCreateSystemThreadProcessHandleNull(SomeThread);
    break;
  case IOCTL_CREATE_SYSTEM_THREAD_HANDLE:
    CreateContextPsCreateSystemThreadProcessHandle(SomeThread);
    break;
  }

  Irp->IoStatus.Status = STATUS_SUCCESS;
  Irp->IoStatus.Information = 0;

  IoCompleteRequest(Irp, IO_NO_INCREMENT);

  return STATUS_SUCCESS;
}

//Device names
WCHAR w_device_name[] = L"\\Device\\Page128SystemThreads";
WCHAR w_dos_device_name[] = L"\\DosDevices\\Page128SystemThreads";

void DriverUnload(PDRIVER_OBJECT DriverObject)
{
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
  Print("PID %p\n\n", PsGetCurrentProcessId());

  NTSTATUS status;

  //Create a device
  UNICODE_STRING device_name{};
  RtlInitUnicodeString(&device_name, w_device_name);

  PDEVICE_OBJECT device_object{};
  if (!NT_SUCCESS(status = IoCreateDevice(
                      DriverObject, 0, &device_name, FILE_DEVICE_UNKNOWN,
                      FILE_DEVICE_SECURE_OPEN, FALSE, &device_object))) {
    DbgPrintLine("Couldn't create device");
    return status;
  }

  //Create a symlink to device
  UNICODE_STRING dos_device_name{};
  RtlInitUnicodeString(&dos_device_name, w_dos_device_name);

  if (!NT_SUCCESS(status =
                      IoCreateSymbolicLink(&dos_device_name, &device_name))) {
    DbgPrintLine("Couldn't create symbolic link");
    IoDeleteDevice(device_object);
    return status;
  }

  //Setup driver handlers
  DriverObject->MajorFunction[IRP_MJ_CREATE] = DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_CLOSE] = DriverCreateClose;
  DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DriverIoctl;
  DriverObject->DriverUnload = DriverUnload;

  return STATUS_SUCCESS;
}