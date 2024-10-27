#pragma once


#ifndef MDL_MANAGER_HPP_INCLUDED
#define MDL_MANAGER_HPP_INCLUDED

#define NDIS_SUPPORT_NDIS6 1
#define NDIS60 1
#define _NDIS_

#include <ntddk.h>

#endif

#ifdef __cplusplus
extern "C" {
#endif

    typedef struct _MDL_REQUEST {
        LIST_ENTRY ListEntry;
        PVOID TargetAddress;
        PVOID Buffer;
        SIZE_T Size;
        PMDL Mdl;
        KEVENT CompletionEvent;
        NTSTATUS Status;
    } MDL_REQUEST, * PMDL_REQUEST;

    typedef struct _MDL_CONTEXT {
        KSPIN_LOCK Lock;
        BOOLEAN IsBusy;
        LIST_ENTRY PendingRequests;
        KDPC ProcessingDpc;
        KTIMER ProcessingTimer;
    } MDL_CONTEXT, * PMDL_CONTEXT;

    VOID InitializeMdlContext(void);
    VOID CleanupMdlContext(void);
    NTSTATUS ProcessMdlOperation(PVOID TargetAddress, PVOID Buffer, SIZE_T Size);
    BOOLEAN IsMdlManagerBusy(void);

#ifdef __cplusplus
}
#endif