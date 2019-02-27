#include "helper.h"

#include <ntifs.h>
#include <wdm.h>

/*
1) Explain how we were able to determine that ExpWorkerThread is the system thread responsible for dequeueing work items and executing them.
Hint: The fastest way is to write a driver

Page131WorkItems: void __cdecl WorkItemRoutine(struct _DEVICE_OBJECT *,void *)
Page131WorkItems: Thread id: cc
Page131WorkItems: Process id: 4
Page131WorkItems: Process filename: System
Page131WorkItems: Thread start address: FFFFF8053AF06FB0
Page131WorkItems: long __cdecl DriverCreateClose(struct _DEVICE_OBJECT *,struct _IRP *)

0: kd> !thread -t cc
THREAD ffff9f8284ae5080  Cid 0004.00cc  Teb: 0000000000000000 Win32Thread: 0000000000000000 WAIT: (WrQueue) KernelMode Non-Alertable
	ffff9f828424c470  PriQueueObject
Not impersonating
DeviceMap                 ffff890703a13780
Owning Process            ffff9f8284267040       Image:         System
Attached Process          N/A            Image:         N/A
Wait Start TickCount      38053          Ticks: 644 (0:00:00:10.062)
Context Switch Count      1565           IdealProcessor: 0
UserTime                  00:00:00.000
KernelTime                00:00:00.125
Win32 Start Address nt!ExpWorkerThread (0xfffff8053af06fb0)
Stack Init ffff9d834e977c90 Current ffff9d834e977800
Base ffff9d834e978000 Limit ffff9d834e972000 Call 0000000000000000
Priority 12 BasePriority 12 PriorityDecrement 0 IoPriority 2 PagePriority 5
Child-SP          RetAddr           : Args to Child                                                           : Call Site
ffff9d83`4e977840 fffff805`3af6ee17 : ffff9f82`84ae5080 00000000`00000000 ffffd781`c9c30080 fffff805`3c319693 : nt!KiSwapContext+0x76
ffff9d83`4e977980 fffff805`3af6e989 : 00000000`00000000 ffff9f82`84b064b0 ffff9f82`84ae5100 00000000`00000000 : nt!KiSwapThread+0x297
ffff9d83`4e977a40 fffff805`3af07be9 : fffff805`3b389200 fffff805`00000000 fffff805`00000000 ffff9f82`962dc080 : nt!KiCommitThreadWait+0x549
ffff9d83`4e977ae0 fffff805`3af07050 : ffff9f82`8424c470 ffff9f82`84ae5080 fffff805`3af7d900 00000000`00000000 : nt!KeRemovePriQueue+0x6f9
ffff9d83`4e977b70 fffff805`3afcb6c5 : ffff9f82`84ae5080 ffff9f82`84267040 ffff9f82`84ae5080 00000000`00000080 : nt!ExpWorkerThread+0xa0
ffff9d83`4e977c10 fffff805`3b06249c : fffff805`3a24b180 ffff9f82`84ae5080 fffff805`3afcb670 00000000`00000000 : nt!PspSystemThreadStartup+0x55
ffff9d83`4e977c60 00000000`00000000 : ffff9d83`4e978000 ffff9d83`4e972000 00000000`00000000 00000000`00000000 : nt!KiStartSystemThread+0x1c

!thread shows the start address and ZwQueryInformationThread can be used to find the thread's start address

2) Explore IoAllocateWorkItem, IoInitializeWorkItem, IoQueueWorkItem,
IopQueueWorkItemProlog, and ExQueueWorkItem, and explain how they
work.

.text:0000000140124300 ; PIO_WORKITEM __stdcall IoAllocateWorkItem(PDEVICE_OBJECT DeviceObject)
.text:0000000140124300                 public IoAllocateWorkItem
.text:0000000140124300 IoAllocateWorkItem proc near            ; DATA XREF: .pdata:00000001403FE20C↓o
.text:0000000140124300                 push    rbx
.text:0000000140124302                 sub     rsp, 20h
.text:0000000140124306                 mov     rbx, rcx
.text:0000000140124309                 mov     edx, 58h        ; "?? sizeof(_IO_WORKITEM)" -> unsigned int64 0x58
.text:000000014012430E                 mov     ecx, 200h       ; POOL_TYPE = NonPagedPoolNx = 0n512 (dt nt!_POOL_TYPE)
.text:0000000140124313                 call    IopVerifierExAllocatePool_0 ; Helper function for allocating objects (Calls ExAllocatePoolWithTag internally)
.text:0000000140124318                 test    rax, rax
.text:000000014012431B                 jz      short loc_140124340
.text:000000014012431D                 and     qword ptr [rax+38h], 0 ; _IO_WORKITEM->WorkOnBehalfThread = NULL
.text:0000000140124322                 lea     rcx, IopProcessWorkItem
.text:0000000140124329                 mov     [rax+28h], rbx  ; _IO_WORKITEM->IoObject = DeviceObject
.text:000000014012432D                 mov     dword ptr [rax+40h], 1 ; _IO_WORKITEM->Type = 1
.text:0000000140124334                 and     qword ptr [rax], 0 ; _IO_WORKITEM->WorkItem.List.Flink = NULL
.text:0000000140124338                 mov     [rax+10h], rcx  ; _IO_WORKITEM->WorkItem.WorkerRoutine = IopProcessWorkItem
.text:000000014012433C                 mov     [rax+18h], rax  ; _IO_WORKITEM->WorkItem.Parameter = _IO_WORKITEM
.text:0000000140124340
.text:0000000140124340 loc_140124340:                          ; CODE XREF: IoAllocateWorkItem+1B↑j
.text:0000000140124340                 add     rsp, 20h
.text:0000000140124344                 pop     rbx
.text:0000000140124345                 retn
.text:0000000140124345 IoAllocateWorkItem endp
.text:0000000140124345

PIO_WORKITEM IoAllocateWorkItem(PDEVICE_OBJECT DeviceObject) {
	PIO_WORKITEM work_item = IopVerifierExAllocatePool_0(NonPagePoolNx, sizeof(_IO_WORKITEM);
	if(work_item) {
		work_item->WorkOnBehalfThread = NULL;
		work_item->IoObject = DeviceObject;
		work_item->Type = 1;
		work_item->WorkItem.List.Flink = NULL;
		work_item->WorkItem.WorkerRoutine = IopProcessWorkItem;
		work_item->WorkItem.Parameter = work_item;
	}
	return NULL;
}

.text:0000000140128480 ; __int64 __fastcall IoInitializeWorkItem(PDEVICE_OBJECT DeviceObject, PIO_WORKITEM WorkItem)
.text:0000000140128480                 public IoInitializeWorkItem
.text:0000000140128480 IoInitializeWorkItem proc near          ; DATA XREF: .rdata:000000014035BC68↓o
.text:0000000140128480                                         ; .pdata:00000001403FE644↓o
.text:0000000140128480
.text:0000000140128480 var_18          = qword ptr -18h
.text:0000000140128480
.text:0000000140128480 ; FUNCTION CHUNK AT .text:0000000140202FF8 SIZE 0000001A BYTES
.text:0000000140128480
.text:0000000140128480                 sub     rsp, 38h
.text:0000000140128484                 movzx   eax, word ptr [rcx] ; DeviceObject->Type
.text:0000000140128487                 mov     r10d, 3
.text:000000014012848D                 sub     ax, r10w        ; DeviceObject->Type - 3
.text:0000000140128491                 lea     r8d, [r10-2]    ; r8 =  1
.text:0000000140128495                 cmp     ax, r8w         ; DeviceObject->Type > 4
.text:0000000140128499                 ja      loc_140202FF8   ; KeBugCheck
.text:000000014012849F                 and     qword ptr [rdx+38h], 0 ; WorkItem->WorkOnBehalfThread = NULL
.text:00000001401284A4                 lea     rax, IopProcessWorkItem
.text:00000001401284AB                 mov     [rdx+40h], r8d  ; WorkItem->Type = 1
.text:00000001401284AF                 mov     [rdx+28h], rcx  ; WorkItem->IoObject = DeviceObject
.text:00000001401284B3                 and     qword ptr [rdx], 0 ; WorkItem->WorkItem.Flink = 0
.text:00000001401284B7                 mov     [rdx+10h], rax  ; WorkItem->WorkItem.WorkerRoutine = IopProcessWorkItem
.text:00000001401284BB                 mov     [rdx+18h], rdx  ; WorkItem->WorkItem.Parameter = WorkItem
.text:00000001401284BF                 add     rsp, 38h
.text:00000001401284C3                 retn
.text:00000001401284C3 IoInitializeWorkItem endp

void IoInitializeWorkItem(PDEVICE_OBJECT DeviceObject, PIO_WORKITEM work_item) {
	if(DeviceObject->Type > 4) {
		KeBugCheck(...);
	}
	work_item->WorkOnBehalfThread = NULL;
	work_item->Type = 1;
	work_item->IoObject = DeviceObject;
	work_item->WorkItem.List.Flink = NULL;
	work_item->WorkItem.WorkerRoutine = IopProcessWorkItem;
	work_item->WorkItem.Parameter = work_item;
}

.text:000000014012AB30 ; void __stdcall IoQueueWorkItem(PIO_WORKITEM IoWorkItem, PIO_WORKITEM_ROUTINE WorkerRoutine, WORK_QUEUE_TYPE QueueType, PVOID Context)
.text:000000014012AB30 public IoQueueWorkItem
.text:000000014012AB30 IoQueueWorkItem proc near
.text:000000014012AB30 push    rbx
.text:000000014012AB32 sub     rsp, 20h
.text:000000014012AB36 and     dword ptr [rcx+40h], 0 ; IoWorkItem->Type = 0
.text:000000014012AB3A mov     ebx, r8d        ; ebx = QueueType
.text:000000014012AB3D mov     r8, r9          ; r8 = Context
.text:000000014012AB40 call    IopQueueWorkItemProlog ; (IoWorkItem, WorkerRoutine, Context)
.text:000000014012AB45 mov     edx, ebx        ; edx = QueueType
.text:000000014012AB47 mov     rcx, rax        ; BugCheckParameter2
.text:000000014012AB4A call    ExQueueWorkItemFromIo ; (IoQueueWorkItemProlog's result, QueueType)
.text:000000014012AB4F add     rsp, 20h
.text:000000014012AB53 pop     rbx
.text:000000014012AB54 retn
.text:000000014012AB54 IoQueueWorkItem end

void __stdcall IoQueueWorkItem(PIO_WORKITEM IoWorkItem, PIO_WORKITEM_ROUTINE WorkerRoutine, WORK_QUEUE_TYPE QueueType, PVOID Context) {
	IoWorkItem->Type = 0;
	IoWorkItem = IopQueueWorkItemProlog(IoWorkItem, WorkerRoutine, Context); //setups more of IoWorkItem such as WorkerRoutine, thread the routine is associated with, update references
	ExQueueWorkItemFromIo(IoWorkItem, QueueType); //actually handles queuing the work item
}

.text:0000000140014FFC ; PIO_WORKITEM __fastcall IopQueueWorkItemProlog(PIO_WORKITEM IoWorkItem, PIO_WORKITEM_ROUTINE WorkerRoutine, PVOID Context)
.text:0000000140014FFC IopQueueWorkItemProlog proc near        ; CODE XREF: IoQueueWorkItemEx+C↑p
.text:0000000140014FFC                                         ; IoQueueWorkItem+10↓p ...
.text:0000000140014FFC
.text:0000000140014FFC var_s0          = dword ptr  8
.text:0000000140014FFC var_s0          = qword ptr  10h
.text:0000000140014FFC var_18          = qword ptr  18h
.text:0000000140014FFC var_10          = qword ptr  20h
.text:0000000140014FFC
.text:0000000140014FFC ; FUNCTION CHUNK AT .text:00000001401CA13C SIZE 0000004B BYTES
.text:0000000140014FFC
.text:0000000140014FFC                 mov     [rsp+var_s0], rbx
.text:0000000140015001                 mov     [rsp+var_18], rbp
.text:0000000140015006                 mov     [rsp+var_10], rsi
.text:000000014001500B                 push    rdi
.text:000000014001500C                 sub     rsp, 20h
.text:0000000140015010                 mov     eax, cs:IopFunctionPointerMask
.text:0000000140015016                 mov     rsi, r8         ; rsi = Context
.text:0000000140015019                 mov     rbp, rdx        ; rbp = WorkerRoutine
.text:000000014001501C                 mov     rbx, rcx        ; rbx = IoWorkItem
.text:000000014001501F                 test    al, 4
.text:0000000140015021                 jnz     loc_1401CA13C   ; IopPointerFunctionMask & 3 != 0
.text:0000000140015027
.text:0000000140015027 loc_140015027:                          ; CODE XREF: IopQueueWorkItemProlog+1B5148↓j
.text:0000000140015027                                         ; IopQueueWorkItemProlog+1B5154↓j
.text:0000000140015027                 xor     eax, eax
.text:0000000140015029                 mov     [rcx+44h], rax
.text:000000014001502D                 mov     [rcx+4Ch], rax  ; memset(IoWorkItem->ActivityId, 0, sizeof(_GUID))

First check is IopPointerFunctionMask's 3rd bit is set. If not, go to loc_1401CA13C (skip checks), else go to loc_140015027

if(IopPointerFunctionMask & 0x3)
	goto loc_1401CA13C
else
	goto loc_140015027 (memset(IoWorkItem->ActivityId, 0, sizeof(_GUID)))

.text:00000001401CA13C loc_1401CA13C:                          ; CODE XREF: IopQueueWorkItemProlog+25↑j
.text:00000001401CA13C                                         ; DATA XREF: .pdata:0000000140408574↓o ...
.text:00000001401CA13C                 mov     eax, cs:IopIrpExtensionStatus
.text:00000001401CA142                 test    al, 1
.text:00000001401CA144                 jz      loc_140015027   ; IopIrpExtensionStatus & 1 == 0
.text:00000001401CA14A                 mov     rax, cr8
.text:00000001401CA14E                 cmp     al, 2
.text:00000001401CA150                 jnb     loc_140015027   ; cr8 >= 2
.text:00000001401CA156                 mov     rax, gs:188h    ; PsGetCurrentThread
.text:00000001401CA15F                 mov     rcx, [rax+758h] ; _ETHREAD->ActivityId
.text:00000001401CA166                 test    rcx, rcx
.text:00000001401CA169                 jz      short loc_1401CA178 ; _ETHREAD->ActivityId == 0
.text:00000001401CA16B                 movups  xmm0, xmmword ptr [rcx]
.text:00000001401CA16E                 movdqu  xmmword ptr [rbx+44h], xmm0 ; IoWorkItem->ActivityId = _ETHREAD->ActivityId + 1
.text:00000001401CA173                 jmp     loc_140015031
.text:00000001401CA178 ; ---------------------------------------------------------------------------
.text:00000001401CA178
.text:00000001401CA178 loc_1401CA178:                          ; CODE XREF: IopQueueWorkItemProlog+1B516D↑j
.text:00000001401CA178                 xor     eax, eax
.text:00000001401CA17A                 mov     [rbx+44h], rax
.text:00000001401CA17E                 mov     [rbx+4Ch], rax  ; memset(IoWorkItem->ActivityId, 0, sizeof(_GUID))
.text:00000001401CA182                 jmp     loc_140015031

Check if IopIrpExtensionStatus's first bit is set and if so, go to return of function.
Then check cr8's second bit (SSE aka XMM instructions) and above bits are enabled, else go to skip checks.
Then check the current thread's ActivityId and set the _GUID of IoWorkItem to be ActivityId + 1
else, go to loc_140015031, which is exactly the same as the skip checks function.

if(IopIrpExtensionStatus & 1 && cr8 >= 2)
	IoWorkItem->_GUID = PsGetCurrentThread()->ActivityId + 1;
All the branches reach loc_140015031

.text:0000000140015031
.text:0000000140015031 loc_140015031:                          ; CODE XREF: IopQueueWorkItemProlog+1B5177↓j
.text:0000000140015031                                         ; IopQueueWorkItemProlog+1B5186↓j
.text:0000000140015031                 mov     eax, gs:2FECh   ; KeGetPcr
.text:0000000140015039                 test    eax, 10001h
.text:000000014001503E                 jnz     short loc_140015094 ; _KPCR & 0x10001 == 0 (Check address)
.text:0000000140015040                 mov     rdi, gs:188h    ; PsGetCurrentThread
.text:0000000140015049                 lea     rdx, [rsp+28h+var_s0] ; rdx = Unknown_ETHREAD
.text:000000014001504E                 mov     rcx, rdi        ; rcx = _ETHREAD
.text:0000000140015051                 call    PsGetWorkOnBehalfThread ; (_ETHREAD, Unknown_ETHREAD)
.text:0000000140015056                 mov     [rbx+38h], rax  ; WorkItem->WorkOnBehalfThread = rax = _ETHREAD->WorkOnBehalf->Thread
.text:000000014001505A                 test    rax, rax
.text:000000014001505D                 jnz     short loc_1400150C2 ; _ETHREAD->WorkOnBehalf->Thread == NULL
.text:000000014001505F                 mov     rax, gs:188h    ; PsGetCurrentThread
.text:0000000140015068                 mov     rcx, [rax+0B8h] ; _ETHREAD->ApcStateFill[0x30]
.text:000000014001506F                 mov     rax, [rcx+3B0h] ; Not sure what this is
.text:0000000140015076                 test    rax, rax
.text:0000000140015079                 jnz     short loc_140015083
.text:000000014001507B                 cmp     cs:PopEnergyEstimationEnabled, al
.text:0000000140015081                 jz      short loc_140015094

Three branches follow here

.text:0000000140015083 loc_140015083:                          ; CODE XREF: IopQueueWorkItemProlog+7D↑j
.text:0000000140015083                 mov     edx, 'tlfD'
.text:0000000140015088                 mov     rcx, rdi        ; _ETHREAD
.text:000000014001508B                 call    ObfReferenceObjectWithTag ; (tlfD, _ETHREAD)
.text:0000000140015090                 mov     [rbx+38h], rdi  ; IoWorkItem->WorkOnBehalfThread = _ETHREAD
.text:0000000140015094
.text:0000000140015094 loc_140015094:                          ; CODE XREF: IopQueueWorkItemProlog+42↑j
.text:0000000140015094                                         ; IopQueueWorkItemProlog+85↑j ...
.text:0000000140015094                 mov     rcx, [rbx+28h]  ; IoWorkItem->IoObject
.text:0000000140015098                 mov     edx, 'tlfD'
.text:000000014001509D                 call    ObfReferenceObjectWithTag
.text:00000001400150A2                 mov     [rbx+20h], rbp
.text:00000001400150A6                 mov     rax, rbx
.text:00000001400150A9                 mov     rbp, [rsp+28h+var_18]
.text:00000001400150AE                 mov     [rbx+30h], rsi
.text:00000001400150B2                 mov     rbx, [rsp+28h+var_s0]
.text:00000001400150B7                 mov     rsi, [rsp+28h+var_10]
.text:00000001400150BC                 add     rsp, 20h
.text:00000001400150C0                 pop     rdi
.text:00000001400150C1                 retn
.text:00000001400150C2 loc_1400150C2:                          ; CODE XREF: IopQueueWorkItemProlog+61↑j
.text:00000001400150C2                 cmp     [rsp+28h+var_s0], 0 ; Unknown == 0
.text:00000001400150C7                 jnz     short loc_140015094 ; Unknown_ETHREAD == 0
.text:00000001400150C9                 mov     edx, 'tlfD'
.text:00000001400150CE                 mov     rcx, rax        ; _ETHREAD->WorkOnBehalfThread
.text:00000001400150D1                 call    ObfReferenceObjectWithTag ; (tlfD, Unknown_ETHREAD)
.text:00000001400150D6                 jmp     short loc_140015094

Check if the address of _KPCR has 0x10001 bits set, then go to loc_140015094
In loc_140015094, ObfReferenceObjectWithTag is called to reference the IoObject that the IoWorkItem is associated with and returns from the function
else, call PsGetWorkOnBehalfThread with the current thread (PsGetCurrentThread) and Unknown_ETHREAD which was passed to this function in register rbx.
PsGetWorkOnBehalfThread gets the current thread->WorkOnBehalfThread and then after, stores it in IoWorkItem->WorkOnBehalfThread
Then check the current thread->WorkOnBehalfThread is NULL and if so, go to loc_1400150C2
at loc_1400150C2, if the Unknown_ETHREAD is not null, reference the current thread->WorkOnBehalfThread, else go to loc_140015094
Back at 000000014001505F, there is a check for current thread->ApcState. I am not sure what this refers to, but if anyone knows, please let me know.
If the check succeeds, then ObfReferenceObjectWithTag is called to reference the current thread
Else, check PopEnergyEstimationEnabled and if that is not zero, ObfReferenceObjectWithTag is called to reference the current thread

//loc_140015031
if(!(KeGetPcr() & 0x10001))
{
	//0000000140015040
	PETHREAD current_thread = PsGetCurrentThread();
	PETHREAD work_on_behalf_thread = PsGetWorkOnBehalfThread(current_thread, Unknown_ETHREAD);
	IoWorkItem->WorkOnBehalfThread = work_on_behalf_thread;

	//loc_1400150C2
	if(work_on_behalf_thread)
	{
		if(Unknown_ETHREAD)
		{
			goto loc_140015094;
		}
		else
		{
			ObfReferenceObjectWithTag("tlfD", work_on_behalf_thread);
		}
		goto loc_140015094;
	}

	//000000014001505F
	if((char*)(current_thread->ApcStateFill[0x30]) + 0x3B0)
	{
		//loc_140015083
		ObfReferenceObjectWithTag("tlfD", current_thread)
		goto loc_140015094;
	}
	else
	{
		//0000000140015079
		if(PopEnergyEstimationEnabled)
		{
			goto loc_140015094;
		}
		else
		{
			goto loc_140015083;
		}
	}
}

Cleaned up:
PIO_WORKITEM __fastcall IopQueueWorkItemProlog(PIO_WORKITEM IoWorkItem, PIO_WORKITEM_ROUTINE WorkerRoutine, PVOID Context)
{
	PETHREAD Unknown_ETHREAD;
	__asm
	{
		mov [Unknown_ETHREAD], rbx
	}

	if(IopPointerFunctionMask & 0x3 && IopIrpExtensionStatus & 1 && cr8 >= 2)
	{
		IoWorkItem->_GUID = PsGetCurrentThread()->ActivityId + 1;
	}
	else
	{
		memset(IoWorkItem->ActivityId, 0, sizeof(_GUID))
	}

	if(!(KeGetPcr() & 0x10001))
	{
		PETHREAD current_thread = PsGetCurrentThread();
		PETHREAD work_on_behalf_thread = PsGetWorkOnBehalfThread(current_thread, Unknown_ETHREAD);
		IoWorkItem->WorkOnBehalfThread = work_on_behalf_thread;

		if(work_on_behalf_thread && Unknown_ETHREAD)
		{
			ObfReferenceObjectWithTag("tlfD", work_on_behalf_thread);
		}
		QWORD ApcState = (char*)(current_thread->ApcStateFill[0x30]) + 0x3B0;
		if(ApcState)
		{
			ObfReferenceObjectWithTag("tlfD", current_thread)
		}
		else if(PopEnergyEstimationEnabled != ApcState)
		{
			ObfReferenceObjectWithTag("tlfD", current_thread);
			IoWorkItem->WorkOnBehalfThread = current_thread);
		}
	}
	ObfReferenceObjectWithTag("tlfD", IoWorkItem->IoObject);
	return IoWorkItem;
}

.text:0000000140014EB0 ; void __stdcall ExQueueWorkItem(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType)
.text:0000000140014EB0 public ExQueueWorkItem
.text:0000000140014EB0 ExQueueWorkItem proc near
.text:0000000140014EB0
.text:0000000140014EB0 var_10= qword ptr -18h
.text:0000000140014EB0 var_20= qword ptr  8
.text:0000000140014EB0
.text:0000000140014EB0 ; FUNCTION CHUNK AT .text:00000001401CA0D2 SIZE 0000001C BYTES
.text:0000000140014EB0
.text:0000000140014EB0 mov     [rsp+var_20], rbx
.text:0000000140014EB5 push    rdi
.text:0000000140014EB6 sub     rsp, 30h
.text:0000000140014EBA movsxd  rbx, edx        ; rbx = QueueType
.text:0000000140014EBD mov     rdi, rcx        ; rdi = WorkItem
.text:0000000140014EC0 mov     edx, ebx        ; QueueType
.text:0000000140014EC2 call    ExpValidateWorkItem ; (WorkItem, QueueType)
.text:0000000140014EC7 mov     ecx, ebx        ; QueueType
.text:0000000140014EC9 call    ExpTypeToPriority ; (QueueType), returns Priority from QueueType
.text:0000000140014ECE mov     r8, cs:PspSystemPartition
.text:0000000140014ED5 or      r9d, 0FFFFFFFFh ; a4
.text:0000000140014ED9 and     dword ptr [rsp+38h+var_10], 0
.text:0000000140014EDE mov     rdx, rdi        ; rdx = IoWorkItem
.text:0000000140014EE1 mov     rcx, [r8+10h]   ; rcx = PspSystemPartition + 0x10
.text:0000000140014EE5 mov     r8d, eax        ; r8 = QueueTypePriority
.text:0000000140014EE8 call    ExpQueueWorkItem ; (PspSystemPartition + 0x10, IoWorkItem, QueueTypePriority)
.text:0000000140014EED test    al, al
.text:0000000140014EEF jz      loc_1401CA0D2   ; !NT_SUCCESS(ExpQueueWorkItem)

void __stdcall ExQueueWorkItem(PWORK_QUEUE_ITEM WorkItem, WORK_QUEUE_TYPE QueueType)
{
	ExpValidateWorkItem(WorkItem, QueueType);
	int QueueTypePriority = ExpTypeToPriority(QueueType);
	int system_thread = (int)((char*)(PspSystemPartition) + 0x10);
	if(!NT_SUCCESS(ExpQueueWorkItem(system_thread, WorkItem, QueueTypePriority))
	{
		KeBugCheck(...);
	}
}

3) Work items and system threads (i.e., those created by PsCreateSystemThread)
are mostly identical in terms of functionality, so explain why DPCs frequently
queue work items to handle requests but never call PsCreateSystemThread.

PsCreateSystemThread is heavy duty -- it creates a whole new thread to execute some function.
Usually DPCs are issued by some higher interrupt and usually, the amount of work to handle some interrupt
should not take too long. This is why queuing as work items is much faster as the system process does not have to
create a whole new thread to handle what is remaining from the interrupt.

4) Write a driver to enumerate all work items on the system and explain the
problems you had to overcome in the process.

Well, things changed in Windows 10. Iterating from PCR to ParentNode (_ENODE)
gives us this:

1: kd> dt _ENODE
nt!_ENODE
   +0x000 Ncb              : _KNODE
   +0x180 HotAddProcessorWorkItem : _WORK_QUEUE_ITEM

Where HotAddProcessorWorkItem is a linked list containing NOT OUR work items (really only ExpNodeHotAddProcessorWorker thread)

Plus another thing is that YOU CAN'T CALL IoFreeWorkItem() OR ELSE THEY GET REMOVED FROM THE LIST ENTRY OF _IO_WORKITEM (I felt dumb for not realizing this :( )
*/

extern "C" {
	NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject,
		_In_ PUNICODE_STRING RegistryPath);
}

using PPsGetProcessImageFileName = PCHAR(*)(PEPROCESS);

UNICODE_STRING
PsGetProcessImageFileNameString =
RTL_CONSTANT_STRING(L"PsGetProcessImageFileName");

using PZwQueryInformationThread = NTSTATUS(*)(
	IN HANDLE          ThreadHandle,
	IN THREADINFOCLASS ThreadInformationClass,
	OUT PVOID          ThreadInformation,
	IN ULONG           ThreadInformationLength,
	OUT PULONG         ReturnLength);

UNICODE_STRING ZwQueryInformationThreadString =
RTL_CONSTANT_STRING(L"ZwQueryInformationThread");

//https://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ps/psquery/class.htm
//enums for ZwQueryThreadInformation

void WorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID context) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(context);
	PrintFunction();

	// To find if this executes under ExpWorkerThread, locate the PID and name of
	// process
	PETHREAD this_thread = PsGetCurrentThread();
	PEPROCESS this_process = IoThreadToProcess(this_thread);

	PPsGetProcessImageFileName PsGetProcessImageFileName =
		reinterpret_cast<PPsGetProcessImageFileName>(
			MmGetSystemRoutineAddress(&PsGetProcessImageFileNameString));

	if (!PsGetProcessImageFileName)
	{
		Print("Failed to get address of PsGetProcessImageFileName\n");
		return;
	}

	PCHAR process_filename = PsGetProcessImageFileName(this_process);

	Print("Thread id: %x\n", PsGetThreadId(this_thread));
	Print("Process id: %x\n", PsGetProcessId(this_process));
	Print("Process filename: %s\n", process_filename);

	PZwQueryInformationThread ZwQueryInformationThread =
		reinterpret_cast<PZwQueryInformationThread>(
			MmGetSystemRoutineAddress(&ZwQueryInformationThreadString));

	if (!ZwQueryInformationThread)
	{
		Print("Failed to get address of ZwQueryInformationThread\n");
		return;
	}

	HANDLE handle{};
	if (!NT_SUCCESS(ObOpenObjectByPointer(this_thread, OBJ_KERNEL_HANDLE, NULL, GENERIC_ALL,
		*PsThreadType, KernelMode, &handle)))
	{
		Print("Failed to open thread object");
		return;
	}

	PVOID thread_start_address{};
	if (!NT_SUCCESS(ZwQueryInformationThread(handle, ThreadQuerySetWin32StartAddress, &thread_start_address, sizeof(thread_start_address), NULL)))
	{
		Print("Failed to get start address of thread");
		return;
	}

	Print("Thread start address: %p\n", thread_start_address);

	ZwClose(handle);
	ObDereferenceObject(this_thread);
}

KEVENT wait_for_enumeration;

void EnumerateWorkItemRoutine(PDEVICE_OBJECT DeviceObject, PVOID context) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(context);
	PrintFunction();

	PIO_WORKITEM* work_items = (PIO_WORKITEM*)context;
	PLIST_ENTRY WorkItemsList = (PLIST_ENTRY)work_items;

	int count{};

	for (PLIST_ENTRY WorkItemsListItr = WorkItemsList; WorkItemsListItr != NULL; WorkItemsListItr = WorkItemsListItr->Blink) {
		if (WorkItemsListItr == WorkItemsList) {
			break;
		}
		PIO_WORKITEM WorkItem = (PIO_WORKITEM)WorkItemsListItr;
		PVOID WorkerRoutine = (PVOID)((PCHAR)(WorkItem)+0x20);
		Print("Work Item count: %d | WorkerRoutine: %p\n", count++, WorkerRoutine);
	}

	KeSetEvent(&wait_for_enumeration, 0, FALSE);

	// Free work item
	IoFreeWorkItem(work_items[1]);
	IoFreeWorkItem(work_items[0]);

	ExFreePool(work_items);
}

void WorkItemNothingRoutine(PDEVICE_OBJECT DeviceObject, PVOID context) {
	UNREFERENCED_PARAMETER(DeviceObject);
	UNREFERENCED_PARAMETER(context);
	PrintFunction();

	KeWaitForSingleObject(&wait_for_enumeration, Executive, KernelMode, FALSE, 0);
}

void EnumerateWorkItems(PDEVICE_OBJECT DeviceObject) {
	/*
	Attempt #1...
	PKPCR kpcr = KeGetPcr();
	struct _KPRCB* kprcb = (struct _KPRCB*)kpcr->CurrentPrcb;
	
	PVOID ENode = *(PVOID*)(((PCHAR)kprcb) + 0xc0);
	PIO_WORKITEM WorkItems = (PIO_WORKITEM)(((PCHAR)ENode) + 0x180);
	PLIST_ENTRY WorkItemsList = (PLIST_ENTRY)WorkItems;
	
	int count{};

	for (PLIST_ENTRY WorkItemsListItr = WorkItemsList->Blink; WorkItemsListItr != NULL && WorkItemsListItr != WorkItemsList; WorkItemsListItr = WorkItemsListItr->Blink) {
		PIO_WORKITEM WorkItem = (PIO_WORKITEM)WorkItemsListItr;
		PVOID WorkerRoutine = (PVOID)((PCHAR)(WorkItem) + 0x20);
		Print("Work Item: %d | WorkerRoutine: %p\n", count++, WorkerRoutine);
	}
	*/
	KeInitializeEvent(&wait_for_enumeration, NotificationEvent, FALSE);

	// Allocate work item
	PIO_WORKITEM work_item1 = IoAllocateWorkItem(DeviceObject);
	PIO_WORKITEM work_item2 = IoAllocateWorkItem(DeviceObject);

	PIO_WORKITEM* work_items = (PIO_WORKITEM*)ExAllocatePool(NonPagedPool, sizeof(work_item1) + sizeof(work_item2));
	work_items[0] = work_item1;
	work_items[1] = work_item2;

	// Queue the work item
	IoQueueWorkItem(work_item1, WorkItemNothingRoutine, NormalWorkQueue, NULL);
	IoQueueWorkItem(work_item2, EnumerateWorkItemRoutine, NormalWorkQueue, work_items);
}

void FindExpWorkerThreadPid(PDEVICE_OBJECT DeviceObject) {
	// Allocate work item
	PIO_WORKITEM work_item = IoAllocateWorkItem(DeviceObject);

	// Queue the work item
	IoQueueWorkItem(work_item, WorkItemRoutine, NormalWorkQueue, NULL);

	// Free work item
	IoFreeWorkItem(work_item);
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
#define IOCTL_CREATE_SYSTEM_EXP_WORKER_THREAD                                  \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

#define IOCTL_CREATE_SYSTEM_ENUM_WORK_ITEMS                                    \
  CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED,                        \
           FILE_READ_DATA | FILE_WRITE_DATA)

// IOCTL handler
NTSTATUS DriverIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	PrintFunction();

	PIO_STACK_LOCATION irp_stack = IoGetCurrentIrpStackLocation(Irp);

	switch (irp_stack->Parameters.DeviceIoControl.IoControlCode) {
	case IOCTL_CREATE_SYSTEM_EXP_WORKER_THREAD:
		FindExpWorkerThreadPid(DeviceObject);
		break;
	case IOCTL_CREATE_SYSTEM_ENUM_WORK_ITEMS:
		EnumerateWorkItems(DeviceObject);
		break;
	}

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}

// Device names
WCHAR w_device_name[] = L"\\Device\\Page131WorkItems";
WCHAR w_dos_device_name[] = L"\\DosDevices\\Page131WorkItems";

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