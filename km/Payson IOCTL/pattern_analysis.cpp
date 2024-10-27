#include "pattern_analysis.hpp"
#include "c2_comm.h"
#include <ntddk.h>
#include <intrin.h>
#include <stdlib.h>


extern "C" ULONG NTAPI RtlRandomEx(PULONG Seed);

UCHAR PATTERN_MASKS_SEQ[] = {
    0xFF, 0xFF, 0xFF, 0x00, // First 3 bytes must match, 4th can vary
    0xFF, 0xFF, 0xFF, 0xFF  // All bytes must match
};


// Global variables for pattern tracking
static SIZE_T g_LastPatternOffset = 0;
static SIZE_T g_PatternInterval = 0;
static LARGE_INTEGER g_LastTimingAdjustment = { 0 };

void AnalyzePatternContext(NeuralNetwork* nn, UCHAR* location, ULONG patternType) {
    if (!nn || !location) return;

    __try {
        // Create a safe buffer for analysis
        UCHAR surroundingBytes[32];
        SIZE_T safeOffset = (location - 16 >= (UCHAR*)nn->eacDriverBase) ? 16 : 0;
        RtlZeroMemory(surroundingBytes, sizeof(surroundingBytes));
        RtlCopyMemory(surroundingBytes, location - safeOffset, min(32, nn->eacDriverSize - ((SIZE_T)location - (SIZE_T)nn->eacDriverBase)));

        switch (patternType) {
        case 0: // Memory Read Pattern
            if (IsMemoryScanningSequence(surroundingBytes)) {
                nn->detectionAttemptObserved = TRUE;
                NeuralNetwork_AdaptTechniques(nn);
                C2_DBG_PRINT("Memory scanning sequence detected\n");
            }
            break;

        case 1: // Memory Address Load
            if (IsAddressValidationSequence(surroundingBytes)) {
                NeuralNetwork_ObfuscateMemory(nn);
                C2_DBG_PRINT("Address validation sequence detected\n");
            }
            break;

        case 2: // Thread Context Access
            if (IsThreadAnalysisSequence(surroundingBytes)) {
                ProtectThreadContext(nn);
                C2_DBG_PRINT("Thread analysis sequence detected\n");
            }
            break;

        case 3: // Module List Access
            if (IsModuleValidationSequence(surroundingBytes)) {
                NeuralNetwork_HideSelf(nn);
                C2_DBG_PRINT("Module validation sequence detected\n");
            }
            break;

        default:
            break;
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        C2_DBG_PRINT("Exception in AnalyzePatternContext: 0x%X\n", GetExceptionCode());
    }
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
    if (!VerifyPatternIntegrity()) {
        return STATUS_INVALID_PARAMETER;
    }

    g_LastPatternOffset = 0;
    g_PatternInterval = 0;
    g_LastTimingAdjustment.QuadPart = 0;

    return STATUS_SUCCESS;
}