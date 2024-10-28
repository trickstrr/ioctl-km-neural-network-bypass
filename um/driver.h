#pragma once
#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <cstdint>
#include <vector>
#include <timeapi.h>

#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "winmm.lib") 

#define REG_KEY_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define REG_VALUE_NAME L"DebuggerValue"

// Forward declarations
namespace driver_status {
    class DriverHealth;
}

struct NNTrainRequest {
    INT32 Security;
    float* Inputs;
    float* Targets;
    int NumSamples;
};

struct NNPredictRequest {
    INT32 Security;
    float* Inputs;
    float* Outputs;
};

namespace mem {
    struct MemoryRegion {
        uint64_t BaseAddress;
        size_t Size;
        DWORD Protection;
    };

    class Driver {
        friend class driver_status::DriverHealth;

    protected:
        HANDLE DriverHandle;
        INT32 ProcessId;
        ULONG RDWCode, SHACode, FGACode, CR3Code;
        ULONG64 SecurityCode;
        ULONG NN_TRAIN_CODE;
        ULONG NN_PREDICT_CODE;

        struct _rw {
            INT32 security;
            INT32 process_id;
            ULONGLONG address;
            ULONGLONG buffer;
            ULONGLONG size;
            BOOLEAN write;
        };

    public:
        Driver();
        ~Driver();

        uintptr_t BaseAddress;

        HANDLE GetDriverHandle() const { return DriverHandle; }
        INT32 GetProcessId() const { return ProcessId; }
        ULONG64 GetSecurityCode() const { return SecurityCode; }

        INT32 find_process(LPCTSTR process);
        uintptr_t get_BaseAddress();
        bool Init();
        void ReadStealthyRegistry(ULONG64* encodedCodes, ULONG64* encodedSecurity);

        bool TrainNeuralNetwork(float* inputs, float* targets, int numSamples);
        bool PredictWithNeuralNetwork(float* inputs, float* outputs);

        bool ReadVirtual(ULONGLONG address, PVOID buffer, SIZE_T size);
        bool WriteVirtual(ULONGLONG address, PVOID buffer, SIZE_T size);
        bool ReadPhysical(ULONGLONG physicalAddress, PVOID buffer, SIZE_T size);
        bool WritePhysical(ULONGLONG physicalAddress, PVOID buffer, SIZE_T size);

        template<typename T>
        T ReadVirtualMemory(ULONGLONG address) {
            T buffer{};
            ReadVirtual(address, &buffer, sizeof(T));
            return buffer;
        }

        template<typename T>
        bool WriteVirtualMemory(ULONGLONG address, const T& value) {
            return WriteVirtual(address, (PVOID)&value, sizeof(T));
        }

        template<typename T>
        T ReadPhysicalMemory(ULONGLONG address) {
            T buffer{};
            ReadPhysical(address, &buffer, sizeof(T));
            return buffer;
        }

        template<typename T>
        bool WritePhysicalMemory(ULONGLONG address, const T& value) {
            return WritePhysical(address, (PVOID)&value, sizeof(T));
        }

        template<typename T>
        T Read(uint64_t address) {
            T buffer{};
            _rw arguments = { 0 };
            arguments.security = SecurityCode;
            arguments.process_id = ProcessId;
            arguments.address = address;
            arguments.buffer = (ULONGLONG)&buffer;
            arguments.size = sizeof(T);
            arguments.write = FALSE;

            DeviceIoControl(
                DriverHandle,
                RDWCode,
                &arguments,
                sizeof(arguments),
                nullptr,
                0,
                nullptr,
                nullptr
            );
            return buffer;
        }

        template<typename T>
        bool Write(uint64_t address, const T& value) {
            _rw arguments = { 0 };
            arguments.security = SecurityCode;
            arguments.process_id = ProcessId;
            arguments.address = address;
            arguments.buffer = (ULONGLONG)&value;
            arguments.size = sizeof(T);
            arguments.write = TRUE;

            return DeviceIoControl(
                DriverHandle,
                RDWCode,
                &arguments,
                sizeof(arguments),
                nullptr,
                0,
                nullptr,
                nullptr
            );
        }

        std::vector<uint64_t> ScanPattern(const char* pattern, const char* mask,
            uint64_t startAddress = 0, uint64_t endAddress = 0, bool firstMatch = false);
        static std::vector<uint8_t> PatternToBytes(const char* pattern);
        bool ProtectMemoryRegion(uint64_t address, size_t size, DWORD protection);
        std::vector<MemoryRegion> GetProcessMemoryMap();
        void RandomizeAccessPattern();
        bool IsDriverHealthy();
    };
}
