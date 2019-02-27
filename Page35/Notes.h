#pragma once
/*
Find modules

https://docs.microsoft.com/en-us/windows-hardware/drivers/ddi/content/aux_klib/nf-aux_klib-auxklibquerymoduleinformation
https://github.com/thomhastings/mimikatz-en/blob/master/driver/modules.c

Object

ObjectHeader
Object - 0x30

ObDeferenceObject -> Deferences ObjectHeader.PointerCount

Work Item
Contains WorkerRoutine
Freeing doesn't matter, only queueing matters in the sense that the ExpWorkerThread adds the Item

IoAllocateWorkItem
ExQueueWorkItem
IoFreeWorkItem

Apc

There are 3 apcs, user, kernel (passive), kernel (apc)
Threads contain apcs (ApcState, two lists)

Apcs are associated with threads (APC_STATE)

Dpc

dispatch level
Each processor has a list of dpcs (ran by Number, which is processor to execute on)

+0x2d80 DpcData : [2] _KDPC_DATA

first is normal, second is threaded dpcs

1st to execute dpc

KiIdleLoop->KiRetireDpcList to process dpc

2nd CPU is at DISPATCH_LEVEL

3rd KiStartDpcThread (system thread) -> KiExecuteDpc -> KiDpcWatchdog




*/