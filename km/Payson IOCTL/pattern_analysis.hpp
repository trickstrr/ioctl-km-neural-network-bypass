#pragma once


#include "nn.h"





#define PATTERN_TYPE_MEMORY_SCAN      0x01
#define PATTERN_TYPE_ADDRESS_VALIDATION 0x02
#define PATTERN_TYPE_THREAD_ANALYSIS    0x03
#define PATTERN_TYPE_MODULE_VALIDATION  0x04



static float fast_log2(float x) {
    union {
        float f;
        UINT32 i;
    } vx = { x };
    union {
        UINT32 i;
        float f;
    } mx = { (vx.i & 0x007FFFFF) | 0x3f000000 };
    float y = vx.i;
    y *= 1.1920928955078125e-7f;

    return y - 124.22551499f
        - 1.498030302f * mx.f
        - 1.72587999f / (0.3520887068f + mx.f);
}


struct DetectionPattern {
    UCHAR pattern[16];
    SIZE_T length;
    const char* description;
};

struct DetectedPattern {
    SIZE_T offset;
    ULONG patternType;
    ULONG frequency;
};

struct PatternStatistics {
    ULONG patternType;
    ULONG frequency;
    SIZE_T avgOffset;
};

typedef struct _PATTERN_ANALYSIS_CONTEXT {
    KSPIN_LOCK Lock;
    PUCHAR SafeBuffer;
    SIZE_T BufferSize;
    BOOLEAN Initialized;
} PATTERN_ANALYSIS_CONTEXT, * PPATTERN_ANALYSIS_CONTEXT;



typedef enum _DEFERRED_ACTION {
    ACTION_ADAPT_TECHNIQUES = 0,
    ACTION_OBFUSCATE_MEMORY,
    ACTION_PROTECT_THREAD,
    ACTION_HIDE_SELF,
    ACTION_MAX
} DEFERRED_ACTION;

#ifdef __cplusplus
extern "C" {
#endif

    NTSTATUS QueueDeferredAction(NeuralNetwork* nn, DEFERRED_ACTION Action);

#ifdef __cplusplus
}
#endif

NTSTATUS InitializePatternAnalysisBuffers(void);
NTSTATUS AnalyzePatternContextEx(NeuralNetwork* nn, UCHAR* location, ULONG patternType);
void CleanupPatternAnalysisContext(void);
void AnalyzePatternDistribution(NeuralNetwork* nn, void* patterns, ULONG count);
BOOLEAN IsMemoryScanningSequence(UCHAR* bytes);
BOOLEAN IsAddressValidationSequence(UCHAR* bytes);
BOOLEAN IsThreadAnalysisSequence(UCHAR* bytes);
BOOLEAN IsModuleValidationSequence(UCHAR* bytes);
BOOLEAN IsPeriodicPattern(SIZE_T offset);
void ProtectThreadContext(NeuralNetwork* nn);
void AdjustTimingBehavior(NeuralNetwork* nn);

NTSTATUS InitializeEACMonitoring(void);
VOID EACMonitorDpcRoutine(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
void CleanupEACMonitoring(void);
NTSTATUS RegisterEACRegion(PVOID BaseAddress, SIZE_T Size, BOOLEAN IsExecutable);
NTSTATUS SafeReadEACMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size);
BOOLEAN IsEACPattern(PUCHAR Address, SIZE_T Size);
void UpdateEACPatterns();
NTSTATUS InitializePatternAnalysis(void);

// EAC-specific
static const DetectionPattern DETECTION_PATTERNS[] = {
    // Memory scanning patterns (EAC specific)
    {
        {0x48, 0x8B, 0x01, 0x48, 0x85, 0xC0, 0x74}, 7,
        "EAC Memory Validation"
    },
    {
        {0x48, 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC9}, 10,
        "EAC Pointer Check"
    },

    // Process/Thread scanning
    {
        {0x65, 0x48, 0x8B, 0x04, 0x25, 0x88, 0x01, 0x00, 0x00}, 9,
        "EAC Thread Check"
    },
    {
        {0x48, 0x8B, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x89, 0x71}, 10,
        "EAC Process Table Access"
    },

    // Module verification
    {
        {0x48, 0x83, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0x00}, 8,
        "EAC Module Presence Check"
    },
    {
        {0xE8, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC0}, 8,
        "EAC Function Verification"
    },

    // Memory protection
    {
        {0x48, 0x8B, 0x45, 0x00, 0x48, 0x89, 0x5D, 0xF0}, 8,
        "EAC Memory Protection Check"
    },
    {
        {0x48, 0x8D, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0xE8}, 8,
        "EAC Integrity Check"
    },

    // Specific EAC patterns
    {
        {0x48, 0x89, 0x5C, 0x24, 0x08, 0x48, 0x89, 0x74, 0x24, 0x10}, 10,
        "EAC Function Entry"
    },
    {
        {0x48, 0x83, 0x3D, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x75}, 9,
        "EAC Status Check"
    },

    // Memory mapping detection
    {
        {0x48, 0x8B, 0x0D, 0xFF, 0xFF, 0xFF, 0xFF, 0x48, 0x85, 0xC9, 0x74}, 11,
        "EAC Memory Map Check"
    },

    // System call monitoring
    {
        {0x4C, 0x8D, 0x5C, 0x24, 0x20, 0x49, 0x8B, 0x5B}, 8,
        "EAC Syscall Monitor"
    }
};

// EAC-specific scanning sequences
static const UCHAR EAC_MEMORY_SCAN_SEQ[] = {
    0x48, 0x8B, 0x01,       // mov rax, [rcx]
    0x48, 0x85, 0xC0,       // test rax, rax
    0x74                    // je short
};

static const UCHAR EAC_VALIDATION_SEQ[] = {
    0x48, 0x8B, 0x0D,       // mov rcx, [rip+offset]
    0x48, 0x85, 0xC9        // test rcx, rcx
};

static const UCHAR EAC_THREAD_SCAN_SEQ[] = {
    0x65, 0x48, 0x8B, 0x04, // gs:[...]
    0x25, 0x88, 0x01        // KTHREAD offset
};

static const UCHAR EAC_MODULE_SCAN_SEQ[] = {
    0x48, 0x83, 0x3D,       // cmp qword ptr
    0xFF, 0xFF, 0xFF, 0xFF  // offset
};

// Pattern matching masks for wildcards
extern UCHAR PATTERN_MASKS_SEQ[];

// Additional helper structures
struct EACPatternContext {
    ULONG patternType;
    SIZE_T offset;
    SIZE_T size;
    BOOLEAN isActive;
};

#define MAX_PATTERN_HISTORY 16
static EACPatternContext PatternHistory[MAX_PATTERN_HISTORY];
static ULONG PatternHistoryIndex = 0;

// Function to track pattern history
static inline void RecordPatternMatch(ULONG type, SIZE_T offset, SIZE_T size) {
    PatternHistory[PatternHistoryIndex].patternType = type;
    PatternHistory[PatternHistoryIndex].offset = offset;
    PatternHistory[PatternHistoryIndex].size = size;
    PatternHistory[PatternHistoryIndex].isActive = TRUE;

    PatternHistoryIndex = (PatternHistoryIndex + 1) % MAX_PATTERN_HISTORY;
}



// Helper function to calculate pattern entropy
static inline float CalculatePatternEntropy(PUCHAR data, SIZE_T size) {
    ULONG frequency[256] = { 0 };
    float entropy = 0.0f;

    for (SIZE_T i = 0; i < size; i++) {
        frequency[data[i]]++;
    }

    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0) {
            float prob = (float)frequency[i] / size;
            entropy -= prob * fast_log2(prob);  
        }
    }

    return entropy;
}