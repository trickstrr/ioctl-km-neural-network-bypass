
#include "mdl_manager.hpp"
#include "c2_comm.h"

static MDL_CONTEXT g_MdlContext = { 0 };

static VOID MdlProcessingDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
);

VOID InitializeMdlContext() {
    KeInitializeSpinLock(&g_MdlContext.Lock);
    InitializeListHead(&g_MdlContext.PendingRequests);
    KeInitializeDpc(&g_MdlContext.ProcessingDpc, MdlProcessingDpcRoutine, NULL);
    KeInitializeTimer(&g_MdlContext.ProcessingTimer);
}

VOID CleanupMdlContext() {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_MdlContext.Lock, &oldIrql);

    if (g_MdlContext.IsBusy) {
        KeCancelTimer(&g_MdlContext.ProcessingTimer);

        // Clean up any pending requests
        while (!IsListEmpty(&g_MdlContext.PendingRequests)) {
            PLIST_ENTRY entry = RemoveHeadList(&g_MdlContext.PendingRequests);
            PMDL_REQUEST request = CONTAINING_RECORD(entry, MDL_REQUEST, ListEntry);
            request->Status = STATUS_CANCELLED;
            KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);
        }
    }

    g_MdlContext.IsBusy = FALSE;
    KeReleaseSpinLock(&g_MdlContext.Lock, oldIrql);
}

BOOLEAN IsMdlManagerBusy() {
    return g_MdlContext.IsBusy;
}

NTSTATUS ProcessMdlOperation(PVOID TargetAddress, PVOID Buffer, SIZE_T Size) {
    KIRQL oldIrql;
    MDL_REQUEST request;
    NTSTATUS status;

    if (!TargetAddress || !Buffer || !Size) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize request
    RtlZeroMemory(&request, sizeof(MDL_REQUEST));
    request.TargetAddress = TargetAddress;
    request.Buffer = Buffer;
    request.Size = Size;
    KeInitializeEvent(&request.CompletionEvent, NotificationEvent, FALSE);

    // Queue request
    KeAcquireSpinLock(&g_MdlContext.Lock, &oldIrql);

    InsertTailList(&g_MdlContext.PendingRequests, &request.ListEntry);

    if (!g_MdlContext.IsBusy) {
        g_MdlContext.IsBusy = TRUE;
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -10000; // 1ms delay
        KeSetTimer(&g_MdlContext.ProcessingTimer, dueTime, &g_MdlContext.ProcessingDpc);
    }

    KeReleaseSpinLock(&g_MdlContext.Lock, oldIrql);

    // Wait for completion
    status = KeWaitForSingleObject(
        &request.CompletionEvent,
        Executive,
        KernelMode,
        FALSE,
        NULL
    );

    if (!NT_SUCCESS(status)) {
        return status;
    }

    return request.Status;
}

static VOID MdlProcessingDpcRoutine(
    PKDPC Dpc,
    PVOID DeferredContext,
    PVOID SystemArgument1,
    PVOID SystemArgument2
) {
    KIRQL oldIrql;
    PLIST_ENTRY entry;
    PMDL_REQUEST request;

    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    KeAcquireSpinLock(&g_MdlContext.Lock, &oldIrql);

    while (!IsListEmpty(&g_MdlContext.PendingRequests)) {
        entry = RemoveHeadList(&g_MdlContext.PendingRequests);
        request = CONTAINING_RECORD(entry, MDL_REQUEST, ListEntry);

        KeReleaseSpinLock(&g_MdlContext.Lock, oldIrql);

        __try {
            // Allocate and build MDL
            request->Mdl = IoAllocateMdl(
                request->TargetAddress,
                (ULONG)request->Size,
                FALSE,
                FALSE,
                NULL
            );

            if (!request->Mdl) {
                request->Status = STATUS_INSUFFICIENT_RESOURCES;
                goto CompleteRequest;
            }

            // Probe and lock pages
            __try {
                MmProbeAndLockPages(request->Mdl, KernelMode, IoReadAccess);
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                request->Status = GetExceptionCode();
                goto CompleteRequest;
            }

            // Map the pages
            PVOID mappedAddress = MmMapLockedPagesSpecifyCache(
                request->Mdl,
                KernelMode,
                MmNonCached,
                NULL,
                FALSE,
                NormalPagePriority
            );

            if (!mappedAddress) {
                request->Status = STATUS_INSUFFICIENT_RESOURCES;
                goto CompleteRequest;
            }

            // Perform the memory copy
            __try {
                RtlCopyMemory(request->Buffer, mappedAddress, request->Size);
                request->Status = STATUS_SUCCESS;
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                request->Status = GetExceptionCode();
            }

            // Unmap the pages
            MmUnmapLockedPages(mappedAddress, request->Mdl);

        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            request->Status = GetExceptionCode();
            C2_DBG_PRINT("Exception in MDL processing: 0x%X\n", request->Status);
        }

    CompleteRequest:
        // Cleanup MDL if it was allocated
        if (request->Mdl) {
            if (request->Mdl->MdlFlags & MDL_PAGES_LOCKED) {
                MmUnlockPages(request->Mdl);
            }
            IoFreeMdl(request->Mdl);
            request->Mdl = NULL;
        }

        // Signal completion
        KeSetEvent(&request->CompletionEvent, IO_NO_INCREMENT, FALSE);

        // Reacquire lock for next iteration
        KeAcquireSpinLock(&g_MdlContext.Lock, &oldIrql);
    }

    g_MdlContext.IsBusy = FALSE;
    KeReleaseSpinLock(&g_MdlContext.Lock, oldIrql);
}

#ifdef DBG
VOID MdlManagerDebugStats() {
    KIRQL oldIrql;
    ULONG pendingRequests = 0;

    KeAcquireSpinLock(&g_MdlContext.Lock, &oldIrql);

    PLIST_ENTRY entry = g_MdlContext.PendingRequests.Flink;
    while (entry != &g_MdlContext.PendingRequests) {
        pendingRequests++;
        entry = entry->Flink;
    }

    KeReleaseSpinLock(&g_MdlContext.Lock, oldIrql);

    C2_DBG_PRINT("MDL Manager Stats:\n");
    C2_DBG_PRINT("Busy: %s\n", g_MdlContext.IsBusy ? "Yes" : "No");
    C2_DBG_PRINT("Pending Requests: %lu\n", pendingRequests);
}
#endif