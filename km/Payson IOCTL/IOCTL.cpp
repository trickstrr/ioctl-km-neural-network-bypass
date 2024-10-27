#include <ntifs.h>
#include <windef.h>
#include <intrin.h>
#include <ntstrsafe.h>


#include "eac.h"
#include "nn.h"
#include "c2_comm.h"
#include "pattern_analysis.hpp"

extern NeuralNetwork* g_neuralNetwork;

UNICODE_STRING DriverName, SymbolicLinkName;
NeuralNetwork* g_neuralNetwork = nullptr;

typedef struct _SystemBigpoolEntry {
    PVOID VirtualAddress;
    ULONG_PTR NonPaged : 1;
    ULONG_PTR SizeInBytes;
    UCHAR Tag[4];
} SystemBigpoolEntry, * PSystemBigpoolEntry;

typedef struct _SystemBigpoolInformation {
    ULONG Count;
    SystemBigpoolEntry AllocatedInfo[1];
} SystemBigpoolInformation, * PSystemBigpoolInformation;

typedef enum _SystemInformationClass {
    SystemModuleInformation = 11,
    SystemBigpoolInformationClass = 0x42,
    
} SystemInformationClass;

extern "C" NTSTATUS NTAPI IoCreateDriver(PUNICODE_STRING DriverName, PDRIVER_INITIALIZE InitializationFunction);
extern "C" PVOID NTAPI PsGetProcessSectionBaseAddress(PEPROCESS Process);
extern "C" NTSTATUS NTAPI ZwQuerySystemInformation(SystemInformationClass systemInformationClass, PVOID systemInformation, ULONG systemInformationLength, PULONG returnLength);

#define REG_KEY_PATH L"\\Registry\\Machine\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define REG_VALUE_NAME L"DebuggerValue"

#define RDWCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8321, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SHACode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8322, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FGACode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8323, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CR3Code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8324, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define Securitycode 0x85F8AC8

#define Win1803 17134
#define Win1809 17763
#define Win1903 18362
#define Win1909 18363
#define Win2004 19041
#define Win20H2 19569
#define Win21H1 20180

#define PageOffsetSize 12


#define NN_TRAIN_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8325, METHOD_BUFFERED, FILE_ANY_ACCESS)
#define NN_PREDICT_CODE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8326, METHOD_BUFFERED, FILE_ANY_ACCESS)

static const UINT64 PageMask = (~0xfull << 8) & 0xfffffffffull;

typedef struct _ReadWriteRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG Address;
    ULONGLONG Buffer;
    ULONGLONG Size;
    BOOLEAN Write;
} ReadWriteRequest, * PReadWriteRequest;

typedef struct _BaseAddressRequest {
    INT32 Security;
    INT32 ProcessId;
    ULONGLONG* Address;
} BaseAddressRequest, * PBaseAddressRequest;

typedef struct _NNTrainRequest {
    INT32 Security;
    float* Inputs;
    float* Targets;
    int NumSamples;
} NNTrainRequest, * PNNTrainRequest;

typedef struct _NNPredictRequest {
    INT32 Security;
    float* Inputs;
    float* Outputs;
} NNPredictRequest, * PNNPredictRequest;

typedef struct _RTL_PROCESS_MODULE_INFORMATION {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

typedef struct _RTL_PROCESS_MODULES {
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;

//-----------NN

NTSTATUS HandleNNTrainRequest(PNNTrainRequest Request) {
    if (Request->Security != Securitycode)
        return STATUS_UNSUCCESSFUL;

    if (!g_neuralNetwork)
        return STATUS_UNSUCCESSFUL;

    NeuralNetwork_Train(g_neuralNetwork, Request->Inputs, Request->Targets, Request->NumSamples);
    return STATUS_SUCCESS;
}

NTSTATUS HandleNNPredictRequest(PNNPredictRequest Request) {
    if (Request->Security != Securitycode)
        return STATUS_UNSUCCESSFUL;

    if (!g_neuralNetwork)
        return STATUS_UNSUCCESSFUL;

    NeuralNetwork_Predict(g_neuralNetwork, Request->Inputs, Request->Outputs);
    return STATUS_SUCCESS;
}


//-----------mem

NTSTATUS WriteToRegistry(ULONG64 value, LPCWSTR valueName)
{
    UNICODE_STRING regPath;
    UNICODE_STRING valueNameUnicode;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;

    RtlInitUnicodeString(&regPath, REG_KEY_PATH);
    InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwCreateKey(&keyHandle, KEY_ALL_ACCESS, &objAttr, 0, NULL, REG_OPTION_NON_VOLATILE, NULL);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&valueNameUnicode, valueName);
    status = ZwSetValueKey(keyHandle, &valueNameUnicode, 0, REG_QWORD, &value, sizeof(ULONG64));

    ZwClose(keyHandle);
    return status;
}

NTSTATUS ReadFromRegistry(PULONG64 value)
{
    UNICODE_STRING regPath;
    UNICODE_STRING valueName;
    OBJECT_ATTRIBUTES objAttr;
    HANDLE keyHandle;
    NTSTATUS status;
    KEY_VALUE_PARTIAL_INFORMATION keyInfo;
    ULONG resultLength;

    RtlInitUnicodeString(&regPath, REG_KEY_PATH);
    InitializeObjectAttributes(&objAttr, &regPath, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenKey(&keyHandle, KEY_READ, &objAttr);
    if (!NT_SUCCESS(status))
        return status;

    RtlInitUnicodeString(&valueName, REG_VALUE_NAME);
    status = ZwQueryValueKey(keyHandle, &valueName, KeyValuePartialInformation, &keyInfo, sizeof(keyInfo), &resultLength);

    if (NT_SUCCESS(status) && keyInfo.Type == REG_QWORD && keyInfo.DataLength == sizeof(ULONG64))
        *value = *(PULONG64)keyInfo.Data;

    ZwClose(keyHandle);
    return status;
}

NTSTATUS ReadPhysicalMemory(PVOID TargetAddress, PVOID Buffer, SIZE_T Size, SIZE_T* BytesRead) {
    MM_COPY_ADDRESS CopyAddress = { 0 };
    CopyAddress.PhysicalAddress.QuadPart = (LONGLONG)TargetAddress;
    return MmCopyMemory(Buffer, CopyAddress, Size, MM_COPY_MEMORY_PHYSICAL, BytesRead);
}

INT32 GetWindowsVersion() {
    RTL_OSVERSIONINFOW VersionInfo = { 0 };
    RtlGetVersion(&VersionInfo);
    switch (VersionInfo.dwBuildNumber) {
    case Win1803:
    case Win1809:
        return 0x0278;
    case Win1903:
    case Win1909:
        return 0x0280;
    case Win2004:
    case Win20H2:
    case Win21H1:
    default:
        return 0x0388;
    }
}

UINT64 GetProcessCr3(PEPROCESS Process) {
    if (!Process) return 0;
    uintptr_t process_dirbase = *(uintptr_t*)((UINT8*)Process + 0x28);
    if (process_dirbase == 0)
    {
        ULONG user_diroffset = GetWindowsVersion();
        process_dirbase = *(uintptr_t*)((UINT8*)Process + user_diroffset);
    }
    if ((process_dirbase >> 0x38) == 0x40)
    {
        uintptr_t SavedDirBase = 0;
        bool Attached = false;
        if (!Attached)
        {
            KAPC_STATE apc_state{};
            KeStackAttachProcess(Process, &apc_state);
            SavedDirBase = __readcr3();
            KeUnstackDetachProcess(&apc_state);
            Attached = true;
        }
        if (SavedDirBase) return SavedDirBase;
    }
    return process_dirbase;
}

UINT64 TranslateLinearAddress(UINT64 DirectoryTableBase, UINT64 VirtualAddress) {
    DirectoryTableBase &= ~0xf;

    UINT64 PageOffset = VirtualAddress & ~(~0ul << PageOffsetSize);
    UINT64 PteIndex = ((VirtualAddress >> 12) & (0x1ffll));
    UINT64 PtIndex = ((VirtualAddress >> 21) & (0x1ffll));
    UINT64 PdIndex = ((VirtualAddress >> 30) & (0x1ffll));
    UINT64 PdpIndex = ((VirtualAddress >> 39) & (0x1ffll));

    SIZE_T ReadSize = 0;
    UINT64 PdpEntry = 0;
    ReadPhysicalMemory(PVOID(DirectoryTableBase + 8 * PdpIndex), &PdpEntry, sizeof(PdpEntry), &ReadSize);
    if (~PdpEntry & 1)
        return 0;

    UINT64 PdEntry = 0;
    ReadPhysicalMemory(PVOID((PdpEntry & PageMask) + 8 * PdIndex), &PdEntry, sizeof(PdEntry), &ReadSize);
    if (~PdEntry & 1)
        return 0;

    if (PdEntry & 0x80)
        return (PdEntry & (~0ull << 42 >> 12)) + (VirtualAddress & ~(~0ull << 30));

    UINT64 PtEntry = 0;
    ReadPhysicalMemory(PVOID((PdEntry & PageMask) + 8 * PtIndex), &PtEntry, sizeof(PtEntry), &ReadSize);
    if (~PtEntry & 1)
        return 0;

    if (PtEntry & 0x80)
        return (PtEntry & PageMask) + (VirtualAddress & ~(~0ull << 21));

    VirtualAddress = 0;
    ReadPhysicalMemory(PVOID((PtEntry & PageMask) + 8 * PteIndex), &VirtualAddress, sizeof(VirtualAddress), &ReadSize);
    VirtualAddress &= PageMask;

    if (!VirtualAddress)
        return 0;

    return VirtualAddress + PageOffset;
}

ULONG64 FindMin(INT32 A, SIZE_T B) {
    INT32 BInt = (INT32)B;
    return (((A) < (BInt)) ? (A) : (BInt));
}

NTSTATUS HandleReadRequest(PReadWriteRequest Request) {
    if (Request->Security != Securitycode)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ProcessBase = GetProcessCr3(Process);
    ObDereferenceObject(Process);

    SIZE_T Offset = NULL;
    SIZE_T TotalSize = Request->Size;

    INT64 PhysicalAddress = TranslateLinearAddress(ProcessBase, (ULONG64)Request->Address + Offset);
    if (!PhysicalAddress)
        return STATUS_UNSUCCESSFUL;

    ULONG64 FinalSize = FindMin(PAGE_SIZE - (PhysicalAddress & 0xFFF), TotalSize);
    SIZE_T BytesRead = NULL;

    ReadPhysicalMemory(PVOID(PhysicalAddress), (PVOID)((ULONG64)Request->Buffer + Offset), FinalSize, &BytesRead);

    return STATUS_SUCCESS;
}

NTSTATUS HandleBaseAddressRequest(PBaseAddressRequest Request) {
    if (Request->Security != Securitycode)
        return STATUS_UNSUCCESSFUL;

    if (!Request->ProcessId)
        return STATUS_UNSUCCESSFUL;

    PEPROCESS Process = NULL;
    PsLookupProcessByProcessId((HANDLE)Request->ProcessId, &Process);
    if (!Process)
        return STATUS_UNSUCCESSFUL;

    ULONGLONG ImageBase = (ULONGLONG)PsGetProcessSectionBaseAddress(Process);
    if (!ImageBase)
        return STATUS_UNSUCCESSFUL;

    RtlCopyMemory(Request->Address, &ImageBase, sizeof(ImageBase));
    ObDereferenceObject(Process);

    return STATUS_SUCCESS;
}

////-----------comm

NTSTATUS IoControlHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    NTSTATUS Status = STATUS_SUCCESS;
    ULONG BytesReturned = 0;
    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    ULONG IoControlCode = Stack->Parameters.DeviceIoControl.IoControlCode;
    ULONG InputBufferLength = Stack->Parameters.DeviceIoControl.InputBufferLength;

    if (IoControlCode == RDWCode) {
        if (InputBufferLength == sizeof(ReadWriteRequest)) {
            PReadWriteRequest Request = (PReadWriteRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleReadRequest(Request);
            BytesReturned = sizeof(ReadWriteRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (IoControlCode == SHACode) {
        if (InputBufferLength == sizeof(BaseAddressRequest)) {
            PBaseAddressRequest Request = (PBaseAddressRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleBaseAddressRequest(Request);
            BytesReturned = sizeof(BaseAddressRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (IoControlCode == NN_TRAIN_CODE) {
        if (InputBufferLength == sizeof(NNTrainRequest)) {
            PNNTrainRequest Request = (PNNTrainRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleNNTrainRequest(Request);
            BytesReturned = sizeof(NNTrainRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }
    else if (IoControlCode == NN_PREDICT_CODE) {
        if (InputBufferLength == sizeof(NNPredictRequest)) {
            PNNPredictRequest Request = (PNNPredictRequest)(Irp->AssociatedIrp.SystemBuffer);
            Status = HandleNNPredictRequest(Request);
            BytesReturned = sizeof(NNPredictRequest);
        }
        else {
            Status = STATUS_INFO_LENGTH_MISMATCH;
        }
    }

    Irp->IoStatus.Status = Status;
    Irp->IoStatus.Information = BytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Status;
}


NTSTATUS UnsupportedDispatch(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    Irp->IoStatus.Status = STATUS_NOT_SUPPORTED;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return Irp->IoStatus.Status;
}

NTSTATUS DispatchHandler(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);

    PIO_STACK_LOCATION Stack = IoGetCurrentIrpStackLocation(Irp);

    switch (Stack->MajorFunction) {
    case IRP_MJ_CREATE:
    case IRP_MJ_CLOSE:
        break;
    default:
        break;
    }

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return Irp->IoStatus.Status;
}


////-----------EAC

PVOID GetEACDriverBase() {
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    NTSTATUS status;
    PRTL_PROCESS_MODULES moduleInfo;
    PVOID eacBase = NULL;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return NULL;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'CADE');
    if (buffer == NULL) {
        return NULL;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return NULL;
    }

    moduleInfo = (PRTL_PROCESS_MODULES)buffer;
    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
        if (strstr((PCHAR)moduleInfo->Modules[i].FullPathName, "EasyAntiCheat_EOS.sys")) {
            eacBase = moduleInfo->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePool(buffer);
    return eacBase;
}

SIZE_T GetEACDriverSize() {
    ULONG bufferSize = 0;
    PVOID buffer = NULL;
    NTSTATUS status;
    PRTL_PROCESS_MODULES moduleInfo;
    SIZE_T eacSize = 0;

    status = ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bufferSize);
    if (status != STATUS_INFO_LENGTH_MISMATCH) {
        return 0;
    }

    buffer = ExAllocatePool2(POOL_FLAG_NON_PAGED, bufferSize, 'CADE');
    if (buffer == NULL) {
        return 0;
    }

    status = ZwQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &bufferSize);
    if (!NT_SUCCESS(status)) {
        ExFreePool(buffer);
        return 0;
    }

    moduleInfo = (PRTL_PROCESS_MODULES)buffer;
    for (ULONG i = 0; i < moduleInfo->NumberOfModules; i++) {
        if (strstr((PCHAR)moduleInfo->Modules[i].FullPathName, "EasyAntiCheat_EOS.sys")) {
            eacSize = moduleInfo->Modules[i].ImageSize;
            break;
        }
    }

    ExFreePool(buffer);
    return eacSize;
}


////-----------Driver Init,Load,Unload

void UnloadDriver(PDRIVER_OBJECT DriverObject) {
    NTSTATUS Status = IoDeleteSymbolicLink(&SymbolicLinkName);

    if (g_neuralNetwork) {
        NeuralNetwork_Destroy(g_neuralNetwork);
        g_neuralNetwork = NULL;
    }

    if (!NT_SUCCESS(Status))
        return;

    IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS InitializeDriver(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS Status = STATUS_SUCCESS;
    PDEVICE_OBJECT DeviceObject = NULL;

    RtlInitUnicodeString(&DriverName, L"\\Device\\{2b3ﬂim90bﬂ9}");
    RtlInitUnicodeString(&SymbolicLinkName, L"\\DosDevices\\{2b3ﬂim90bﬂ9}");

    Status = IoCreateDevice(DriverObject, 0, &DriverName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &DeviceObject);
    if (!NT_SUCCESS(Status)) {
        return Status;
    }

    Status = IoCreateSymbolicLink(&SymbolicLinkName, &DriverName);
    if (!NT_SUCCESS(Status)) {
        IoDeleteDevice(DeviceObject);
        return Status;
    }

    for (int i = 0; i <= IRP_MJ_MAXIMUM_FUNCTION; i++) {
        DriverObject->MajorFunction[i] = &UnsupportedDispatch;
    }

    DriverObject->MajorFunction[IRP_MJ_CREATE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = &DispatchHandler;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = &IoControlHandler;
    DriverObject->DriverUnload = &UnloadDriver;

    DeviceObject->Flags |= DO_BUFFERED_IO;
    DeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return Status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    NTSTATUS status;
    PVOID eacDriverBase;
    SIZE_T eacDriverSize;

    status = InitializeFunctionPointers();
    if (!NT_SUCCESS(status)) {
        C2_DBG_PRINT("Failed to initialize function pointers: %08X\n", status);
        return status;
    }

    UNREFERENCED_PARAMETER(RegistryPath);

    // Write encoded codes to registry
    ULONG64 encodedCodes = (ULONG64)RDWCode | ((ULONG64)SHACode << 16) | ((ULONG64)FGACode << 32) | ((ULONG64)CR3Code << 48);
    WriteToRegistry(encodedCodes, L"EncodedCodes");
    WriteToRegistry((ULONG64)Securitycode, L"EncodedSecurity");

    // Create neural network
    g_neuralNetwork = NeuralNetwork_Create(10, 20, 5);
    if (!g_neuralNetwork) return STATUS_INSUFFICIENT_RESOURCES;

    // Initialize stability monitor
    NeuralNetwork_InitializeStabilityMonitor(g_neuralNetwork);

    // Get EAC driver information first
    eacDriverBase = GetEACDriverBase();
    eacDriverSize = GetEACDriverSize();

    if (!eacDriverBase || !eacDriverSize) {
        C2_DBG_PRINT("Failed to get EAC driver information\n");
        NeuralNetwork_Destroy(g_neuralNetwork);
        return STATUS_UNSUCCESSFUL;
    }

    // Now initialize pattern analysis with EAC information
    status = InitializePatternAnalysis();
    if (!NT_SUCCESS(status)) {
        C2_DBG_PRINT("Failed to initialize pattern analysis: %08X\n", status);
        NeuralNetwork_Destroy(g_neuralNetwork);
        return status;
    }

    // Initialize monitoring and protection
    NeuralNetwork_MonitorEAC(g_neuralNetwork, eacDriverBase, eacDriverSize);
    //NeuralNetwork_InitializeStealthHooks(g_neuralNetwork);  //need to be implemented 
    NeuralNetwork_AdaptSelf(g_neuralNetwork, DriverObject->DriverStart, DriverObject->DriverSize);

    // Apply protection layers
    NeuralNetwork_ObfuscateMemory(g_neuralNetwork);
    NeuralNetwork_CreateDecoys(g_neuralNetwork);
    NeuralNetwork_ReduceMemoryFootprint(g_neuralNetwork);
    NeuralNetwork_OptimizePerformance(g_neuralNetwork);

    // Start evasion thread
    HANDLE threadHandle;
    PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
        (PKSTART_ROUTINE)NeuralNetwork_EvadeDetection, g_neuralNetwork);

    // Initialize WSK and C2 communication
    status = InitializeWskData();
    if (NT_SUCCESS(status)) {
        PsCreateSystemThread(&threadHandle, THREAD_ALL_ACCESS, NULL, NULL, NULL,
            (PKSTART_ROUTINE)NeuralNetwork_CommunicateWithC2, g_neuralNetwork);
    }

    // Apply additional protections
    NeuralNetwork_ApplyPolymorphicObfuscation(g_neuralNetwork);
    NeuralNetwork_AdaptTechniques(g_neuralNetwork);

    C2_DBG_PRINT("\nNeural network fully initialized and operational.");
    C2_DBG_PRINT("\nMade by guns.lol/trickstrr");

    return IoCreateDriver(NULL, &InitializeDriver);
}