#pragma once

#include <ntddk.h>
#include <ntifs.h>
#include <wdm.h>

// 5

/*
1: kd> dt nt!_KDPC
  +0x000 TargetInfoAsUlong : Uint4B
  +0x000 Type             : UChar
  +0x001 Importance       : UChar
  +0x002 Number           : Uint2B
  +0x008 DpcListEntry     : _SINGLE_LIST_ENTRY
  +0x010 ProcessorHistory : Uint8B
  +0x018 DeferredRoutine  : Ptr64     void 
  +0x020 DeferredContext  : Ptr64 Void
  +0x028 SystemArgument1  : Ptr64 Void
  +0x030 SystemArgument2  : Ptr64 Void
  +0x038 DpcData          : Ptr64 Void

1: kd> u nt!KeInitializeDpc
  nt!KeInitializeDpc:
  fffff805`3af8d170 33c0            xor     eax,eax
  fffff805`3af8d172 c70113010000    mov     dword ptr [rcx],113h
  fffff805`3af8d178 48894138        mov     qword ptr [rcx+38h],rax
  fffff805`3af8d17c 48894110        mov     qword ptr [rcx+10h],rax
  fffff805`3af8d180 48895118        mov     qword ptr [rcx+18h],rdx
  fffff805`3af8d184 4c894120        mov     qword ptr [rcx+20h],r8
  fffff805`3af8d188 c3              ret
  fffff805`3af8d189 cc              int     3
*/

void KeInitializeDpc(
  __drv_aliasesMem PRKDPC Dpc,
  PKDEFERRED_ROUTINE      DeferredRoutine,
  __drv_aliasesMem PVOID  DeferredContext
)
{
  int zero = 0;
  Dpc->TargetInfoAsUlong = 0x113;
  Dpc->DpcData = 0;
  Dpc->ProcessorHistory = 0;
  Dpc->DeferredRoutine = DeferredRoutine;
  Dpc->DeferredContext = DeferredContext;
}

//KeInitializeApc not avaliable

/*
1: kd> uf ObFastDereferenceObject
nt!ObFastDereferenceObject:
fffff805`3af65ba0 4883ec28        sub     rsp,28h
fffff805`3af65ba4 4c8bca          mov     r9,rdx
fffff805`3af65ba7 0f0d09          prefetchw [rcx]
fffff805`3af65baa 488b01          mov     rax,qword ptr [rcx]
fffff805`3af65bad 4c8bc0          mov     r8,rax
fffff805`3af65bb0 4c33c2          xor     r8,rdx
fffff805`3af65bb3 4983f80f        cmp     r8,0Fh
fffff805`3af65bb7 7310            jae     nt!ObFastDereferenceObject+0x29 (fffff805`3af65bc9)  Branch

nt!ObFastDereferenceObject+0x19:
fffff805`3af65bb9 4c8d4001        lea     r8,[rax+1]
fffff805`3af65bbd f04c0fb101      lock cmpxchg qword ptr [rcx],r8
fffff805`3af65bc2 750f            jne     nt!ObFastDereferenceObject+0x33 (fffff805`3af65bd3)  Branch

nt!ObFastDereferenceObject+0x24:
fffff805`3af65bc4 4883c428        add     rsp,28h
fffff805`3af65bc8 c3              ret

nt!ObFastDereferenceObject+0x29:
fffff805`3af65bc9 498bc9          mov     rcx,r9
fffff805`3af65bcc e84f070000      call    nt!ObfDereferenceObject (fffff805`3af66320)
fffff805`3af65bd1 ebf1            jmp     nt!ObFastDereferenceObject+0x24 (fffff805`3af65bc4)  Branch

nt!ObFastDereferenceObject+0x33:
fffff805`3af65bd3 488bd0          mov     rdx,rax
fffff805`3af65bd6 4933d1          xor     rdx,r9
fffff805`3af65bd9 4883fa0f        cmp     rdx,0Fh
fffff805`3af65bdd 72da            jb      nt!ObFastDereferenceObject+0x19 (fffff805`3af65bb9)  Branch

nt!ObFastDereferenceObject+0x3f:
fffff805`3af65bdf ebe8            jmp     nt!ObFastDereferenceObject+0x29 (fffff805`3af65bc9)  Branch

1: kd> dt nt!_EX_FAST_REF
   +0x000 Object           : Ptr64 Void
   +0x000 RefCnt           : Pos 0, 4 Bits
   +0x000 Value            : Uint8B


VOID
FASTCALL
ObFastDereferenceObject (
    IN   FastRef,
    IN PVOID Object
    )

*/

typedef struct
{
  union
  {
    PVOID Object;
    int RefCnt:4;
    UINT8 Value;
  };
} EX_FAST_REF, *PEX_FAST_REF;

void
FASTCALL
ObFastDereferenceObject(
  IN PEX_FAST_REF FastRef,
  IN PVOID Object
)
{
  while (FastRef->RefCnt < 0xF && FastRef->Object == Object)
  {
    if (_InterlockedCompareExchange((LONG*)FastRef, FastRef->RefCnt + 1, FastRef->RefCnt))
    {
      return;
    }
  }
  ObfDereferenceObject(Object);
}

/*
nt!KeInitializeQueue:
fffff805`3afbef50 4053            push    rbx
fffff805`3afbef52 4883ec20        sub     rsp,20h
fffff805`3afbef56 488bd9          mov     rbx,rcx
fffff805`3afbef59 c60104          mov     byte ptr [rcx],4
fffff805`3afbef5c 33c9            xor     ecx,ecx
fffff805`3afbef5e 66c743010010    mov     word ptr [rbx+1],1000h
fffff805`3afbef64 488d4308        lea     rax,[rbx+8]
fffff805`3afbef68 894b04          mov     dword ptr [rbx+4],ecx
1: kd> uf KeInitializeQueue
nt!KeInitializeQueue:
fffff805`3afbef50 4053            push    rbx
fffff805`3afbef52 4883ec20        sub     rsp,20h
fffff805`3afbef56 488bd9          mov     rbx,rcx
fffff805`3afbef59 c60104          mov     byte ptr [rcx],4
fffff805`3afbef5c 33c9            xor     ecx,ecx
fffff805`3afbef5e 66c743010010    mov     word ptr [rbx+1],1000h
fffff805`3afbef64 488d4308        lea     rax,[rbx+8]
fffff805`3afbef68 894b04          mov     dword ptr [rbx+4],ecx
fffff805`3afbef6b 48894008        mov     qword ptr [rax+8],rax
fffff805`3afbef6f 488900          mov     qword ptr [rax],rax
fffff805`3afbef72 488d4318        lea     rax,[rbx+18h]
fffff805`3afbef76 48894008        mov     qword ptr [rax+8],rax
fffff805`3afbef7a 488900          mov     qword ptr [rax],rax
fffff805`3afbef7d 488d4330        lea     rax,[rbx+30h]
fffff805`3afbef81 48894008        mov     qword ptr [rax+8],rax
fffff805`3afbef85 488900          mov     qword ptr [rax],rax
fffff805`3afbef88 894b28          mov     dword ptr [rbx+28h],ecx
fffff805`3afbef8b 85d2            test    edx,edx
fffff805`3afbef8d 750c            jne     nt!KeInitializeQueue+0x4b (fffff805`3afbef9b)  Branch

nt!KeInitializeQueue+0x3f:
fffff805`3afbef8f b9ffff0000      mov     ecx,0FFFFh
fffff805`3afbef94 e8a714f6ff      call    nt!KeQueryActiveProcessorCountEx (fffff805`3af20440)
fffff805`3afbef99 8bd0            mov     edx,eax

nt!KeInitializeQueue+0x4b:
fffff805`3afbef9b 89532c          mov     dword ptr [rbx+2Ch],edx
fffff805`3afbef9e 4883c420        add     rsp,20h
fffff805`3afbefa2 5b              pop     rbx
fffff805`3afbefa3 c3              ret

1: kd> dt nt!_DISPATCHER_HEADER
   +0x000 Lock             : Int4B
   +0x000 LockNV           : Int4B
   +0x000 Type             : UChar
   +0x001 Signalling       : UChar
   +0x002 Size             : UChar
   +0x003 Reserved1        : UChar
   +0x000 TimerType        : UChar
   +0x001 TimerControlFlags : UChar
   +0x001 Absolute         : Pos 0, 1 Bit
   +0x001 Wake             : Pos 1, 1 Bit
   +0x001 EncodedTolerableDelay : Pos 2, 6 Bits
   +0x002 Hand             : UChar
   +0x003 TimerMiscFlags   : UChar
   +0x003 Index            : Pos 0, 6 Bits
   +0x003 Inserted         : Pos 6, 1 Bit
   +0x003 Expired          : Pos 7, 1 Bit
   +0x000 Timer2Type       : UChar
   +0x001 Timer2Flags      : UChar
   +0x001 Timer2Inserted   : Pos 0, 1 Bit
   +0x001 Timer2Expiring   : Pos 1, 1 Bit
   +0x001 Timer2CancelPending : Pos 2, 1 Bit
   +0x001 Timer2SetPending : Pos 3, 1 Bit
   +0x001 Timer2Running    : Pos 4, 1 Bit
   +0x001 Timer2Disabled   : Pos 5, 1 Bit
   +0x001 Timer2ReservedFlags : Pos 6, 2 Bits
   +0x002 Timer2ComponentId : UChar
   +0x003 Timer2RelativeId : UChar
   +0x000 QueueType        : UChar
   +0x001 QueueControlFlags : UChar
   +0x001 Abandoned        : Pos 0, 1 Bit
   +0x001 DisableIncrement : Pos 1, 1 Bit
   +0x001 QueueReservedControlFlags : Pos 2, 6 Bits
   +0x002 QueueSize        : UChar
   +0x003 QueueReserved    : UChar
   +0x000 ThreadType       : UChar
   +0x001 ThreadReserved   : UChar
   +0x002 ThreadControlFlags : UChar
   +0x002 CycleProfiling   : Pos 0, 1 Bit
   +0x002 CounterProfiling : Pos 1, 1 Bit
   +0x002 GroupScheduling  : Pos 2, 1 Bit
   +0x002 AffinitySet      : Pos 3, 1 Bit
   +0x002 Tagged           : Pos 4, 1 Bit
   +0x002 EnergyProfiling  : Pos 5, 1 Bit
   +0x002 SchedulerAssist  : Pos 6, 1 Bit
   +0x002 ThreadReservedControlFlags : Pos 7, 1 Bit
   +0x003 DebugActive      : UChar
   +0x003 ActiveDR7        : Pos 0, 1 Bit
   +0x003 Instrumented     : Pos 1, 1 Bit
   +0x003 Minimal          : Pos 2, 1 Bit
   +0x003 Reserved4        : Pos 3, 3 Bits
   +0x003 UmsScheduled     : Pos 6, 1 Bit
   +0x003 UmsPrimary       : Pos 7, 1 Bit
   +0x000 MutantType       : UChar
   +0x001 MutantSize       : UChar
   +0x002 DpcActive        : UChar
   +0x003 MutantReserved   : UChar
   +0x004 SignalState      : Int4B
   +0x008 WaitListHead     : _LIST_ENTRY

1: kd> dt nt!_KQUEUE
   +0x000 Header           : _DISPATCHER_HEADER
   +0x018 EntryListHead    : _LIST_ENTRY
   +0x028 CurrentCount     : Uint4B
   +0x02c MaximumCount     : Uint4B
   +0x030 ThreadListHead   : _LIST_ENTRY
*/

void KeInitializeQueue(
  PRKQUEUE Queue,
  ULONG    Count
)
{
  Queue->Header.QueueType = 4;
  Queue->Header.QueueControlFlags = 0x10;
  Queue->Header.QueueSize = 0x0;
  Queue->Header.SignalState = 0x0;

  Queue->Header.WaitListHead.Flink = &Queue->Header.WaitListHead;
  Queue->Header.WaitListHead.Blink = &Queue->Header.WaitListHead;

  Queue->EntryListHead.Flink = &Queue->EntryListHead;
  Queue->EntryListHead.Blink = &Queue->EntryListHead;

  Queue->ThreadListHead.Flink = &Queue->ThreadListHead;
  Queue->ThreadListHead.Blink = &Queue->ThreadListHead;

  Queue->CurrentCount = 0;

  if (!Count)
  {
    Queue->MaximumCount = KeQueryActiveProcessorCountEx(0xFFFF);
  }
  else
  {
    Queue->MaximumCount = Count;
  }


}


// 6

/*
sub_13842 proc near
mov     eax, [ecx+60h]
push    esi
mov     esi, [edx+8]
dec     byte ptr [ecx+23h]
sub     eax, 24h
mov     [ecx+60h], eax
mov     [eax+14h], edx
movzx   eax, byte ptr [eax]
push    ecx
push    edx
call    dword ptr [esi+eax*4+38h]
pop     esi
retn
sub_13842 endp
*/

struct sub_13742_data2;

struct sub_sub_13742_data1
{
  char unknown1[0x14];
  sub_13742_data2* sub_13742_data2_ptr;
};

struct sub_13742_data1
{
  char unknown1[0x23];
  //0x23
  char val1;
  //0x60
  char unknown2[0x36];
  sub_sub_13742_data1* sub_data1;
};

typedef int (*sub_13742_func)(sub_13742_data1 *, sub_13742_data2 *);

struct sub_13742_data2_function_array
{
  char unknown1[0x34];
  sub_13742_func *function_array;
};

struct sub_13742_data2
{
  char unknown1[0x8];
  sub_13742_data2_function_array* val1;
};

int __fastcall sub_13742(sub_13742_data1* data1, sub_13742_data2* data2)
{
  sub_sub_13742_data1* data1_sub_data1 = data1->sub_data1;
  sub_13742_data2_function_array* data2_function_array = data2->val1;

  data1->val1--;

  data1_sub_data1 = (sub_sub_13742_data1*)((char*)data1_sub_data1 - 0x24);
  data1->sub_data1 = data1_sub_data1;

  data1_sub_data1->sub_13742_data2_ptr = data2;

  //sign extend byte
  char array_index = ((int)data1_sub_data1 & 8);
  return data2_function_array->function_array[array_index](data1, data2);
}

// 7

typedef int (*sub_10BB6_func)(char* section_table, int some_val);

char* sub_10BB6(char* image_base, int some_val)
{
  INT32 pe_offset = *(INT32*)(image_base + 0x38);
  char* pe_header = image_base + pe_offset;
  INT16 size_of_optional_header = *(INT16*)(pe_header + 0x14);

  INT16 number_of_sections = *(INT16*)(pe_header + 0x6);
  if (number_of_sections)
  {
    int current_section = 0;
    char* section_tables = pe_header + size_of_optional_header + 0x18;
    do
    {
      int result = sub_10BB6_func(section_tables, some_val);
      if (!result)
      {
        return section_tables;
      }
      section_tables += 0x28;
      current_section++;
    } while (current_section < number_of_sections);
  }
  else
  {
    return 0;
  }
}

// 8

void sub_11732(int a)
{
  switch (a)
  {
  case 12:

    break;
  case 11:
    break;
  case 10:
    break;
  case 9:
    break;
  default:

  }

}
