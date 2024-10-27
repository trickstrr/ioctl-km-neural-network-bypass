#pragma once

#include <ntddk.h>

typedef struct _NeuralNetwork {
    int inputNodes;
    int hiddenNodes;
    int outputNodes;

    float* weightsInputHidden;
    float* weightsHiddenOutput;
    float* biasHidden;
    float* biasOutput;

    float (*activationFunction)(float);
    void (*forwardPropagate)(struct _NeuralNetwork*, float*, float*);

    PVOID eacDriverBase;
    SIZE_T eacDriverSize;
    UCHAR* eacCodeSnapshot;

    PVOID ownDriverBase;
    SIZE_T ownDriverSize;
    UCHAR* ownCodeSnapshot;

    ULONG lastObfuscationKey;
    ULONG eacDetectionCount;

    BOOLEAN detectionAttemptObserved;
    BOOLEAN highCpuUsageObserved;
    BOOLEAN memoryPressureObserved;

    //scoringg
    ULONG lastEacDetectionCount;
    LARGE_INTEGER lastDetectionTime;
    float lastHiddenDriverScore;
    ULONG memoryObfuscationLevel;
    ULONG lastMemoryObfuscationLevel;
    ULONG decoyCount;
    ULONG lastDecoyCount;
    float performanceScore;
    float lastPerformanceScore;
    SIZE_T memoryFootprint;
    SIZE_T lastMemoryFootprint;

    //crashprevention
    LONG crashCount;
    LONG operationCount;
    float stabilityScore;
    KDPC stabilityCheckDpc;
    KTIMER stabilityCheckTimer;

} NeuralNetwork;

#define MAX_HOOKS 10
typedef struct _HOOK_DATA {
    PVOID OriginalFunction;
    PVOID HookFunction;
    UINT8 OriginalBytes[16];
    SIZE_T PatchSize;
} HOOK_DATA, * PHOOK_DATA;

extern HOOK_DATA g_Hooks[MAX_HOOKS];
extern INT g_HookCount;
extern NeuralNetwork* g_neuralNetwork;


NeuralNetwork* NeuralNetwork_Create(int inputNodes, int hiddenNodes, int outputNodes);
void NeuralNetwork_Destroy(NeuralNetwork* nn);


void NeuralNetwork_Train(NeuralNetwork* nn, float* inputs, float* targets, int numSamples);
void NeuralNetwork_Predict(NeuralNetwork* nn, float* inputs, float* outputs);

//Hooks
void NeuralNetwork_InitializeStealthHooks(NeuralNetwork* nn);
void NeuralNetwork_InstallHook(PVOID TargetFunction, PVOID HookFunction, PHOOK_DATA HookData);
void NeuralNetwork_RemoveHook(PHOOK_DATA HookData);
void NeuralNetwork_ProcessHookedData(NeuralNetwork* nn, PVOID Data, SIZE_T DataSize);
NTSTATUS HookedEacCheckMemory(PVOID Address, SIZE_T Size);

// Static function equivalents
void* NeuralNetwork_AllocateMemory(size_t size);
void NeuralNetwork_FreeMemory(void* p);

void NeuralNetwork_MonitorEAC(NeuralNetwork* nn, PVOID eacDriverBase, SIZE_T eacDriverSize);
PVOID FindEacFunction(PVOID EacBase, const char* FunctionName);

void NeuralNetwork_AdaptSelf(NeuralNetwork* nn, PVOID ownDriverBase, SIZE_T ownDriverSize);
void NeuralNetwork_RewriteOwnCode(NeuralNetwork* nn, PVOID targetAddress, UCHAR* newCode, SIZE_T codeSize);

void NeuralNetwork_HideSelf(NeuralNetwork* nn);
void NeuralNetwork_UnhideSelf(NeuralNetwork* nn);
void NeuralNetwork_ModifyMemory(PVOID targetAddress, PVOID sourceData, SIZE_T size);
void NeuralNetwork_ConcealMemoryRegion(PVOID start, SIZE_T size);

void NeuralNetwork_EvadeDetection(NeuralNetwork* nn);
void NeuralNetwork_AnalyzeEACBehavior(NeuralNetwork* nn);
void NeuralNetwork_AdaptTechniques(NeuralNetwork* nn);
void NeuralNetwork_CreateDecoys(NeuralNetwork* nn);
void NeuralNetwork_ObfuscateMemory(NeuralNetwork* nn);

void NeuralNetwork_IncreaseObfuscation(NeuralNetwork* nn);
void NeuralNetwork_ApplyPolymorphicObfuscation(NeuralNetwork* nn);
void NeuralNetwork_IncreasedEACMonitoring(NeuralNetwork* nn);
void NeuralNetwork_OptimizePerformance(NeuralNetwork* nn);
void NeuralNetwork_ReduceMemoryFootprint(NeuralNetwork* nn);

NTSTATUS FindSuitableDriversForHiding(PVOID* CandidateDrivers, PULONG CandidateCount);
void NeuralNetwork_HideInLegitimateDriver(NeuralNetwork* nn, PDRIVER_OBJECT DriverObject);
void NeuralNetwork_Predict(NeuralNetwork* nn, float* inputs, float* outputs);
void NeuralNetwork_Train(NeuralNetwork* nn, float* inputs, float* targets, int numSamples);

//crash prevent
void NeuralNetwork_InitializeStabilityMonitor(NeuralNetwork* nn);
void NeuralNetwork_StabilityCheck(PKDPC Dpc, PVOID DeferredContext, PVOID SystemArgument1, PVOID SystemArgument2);
BOOLEAN NeuralNetwork_IsOperationSafe(NeuralNetwork* nn);
void NeuralNetwork_AdjustBehavior(NeuralNetwork* nn);

// Helper functions

float NeuralNetwork_Sigmoid(float x);
float NeuralNetwork_SigmoidDerivative(float x);
ULONG RotateLeft(ULONG value, UCHAR shift);
ULONG GeneratePseudoRandomNumber(PULONG Seed);
NTSTATUS InitializeFunctionPointers();