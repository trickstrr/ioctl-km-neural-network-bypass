#include "driver.h"
#include "status.h"
#include <random>

namespace mem {

    Driver::Driver() : DriverHandle(INVALID_HANDLE_VALUE), ProcessId(0), BaseAddress(0) {
        RDWCode = SHACode = FGACode = CR3Code = 0;
        SecurityCode = 0;
        NN_TRAIN_CODE = NN_PREDICT_CODE = 0;
    }

    Driver::~Driver() {
        if (DriverHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(DriverHandle);
        }
    }

    void Driver::ReadStealthyRegistry(ULONG64* encodedCodes, ULONG64* encodedSecurity) {
        HKEY hKey;
        auto NtQueryValueKey = reinterpret_cast<PNtQueryValueKey>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "NtQueryValueKey"
        ));

        auto RtlInitUnicodeString = reinterpret_cast<PRtlInitUnicodeString>(GetProcAddress(
            GetModuleHandleW(L"ntdll.dll"),
            "RtlInitUnicodeString"
        ));

        if (!NtQueryValueKey || !RtlInitUnicodeString) {
            return;
        }

        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            REG_KEY_PATH,
            0,
            KEY_READ,
            &hKey) == ERROR_SUCCESS)
        {
            UNICODE_STRING valueName;
            KEY_VALUE_PARTIAL_INFORMATION keyInfo;
            ULONG resultLength;

            RtlInitUnicodeString(&valueName, L"EncodedCodes");
            NTSTATUS status = NtQueryValueKey(
                hKey,
                &valueName,
                KeyValuePartialInformation,
                &keyInfo,
                sizeof(keyInfo),
                &resultLength
            );

            if (NT_SUCCESS(status) &&
                keyInfo.Type == REG_QWORD &&
                keyInfo.DataLength == sizeof(ULONG64))
            {
                *encodedCodes = *(PULONG64)keyInfo.Data;
            }

            RtlInitUnicodeString(&valueName, L"EncodedSecurity");
            status = NtQueryValueKey(
                hKey,
                &valueName,
                KeyValuePartialInformation,
                &keyInfo,
                sizeof(keyInfo),
                &resultLength
            );

            if (NT_SUCCESS(status) &&
                keyInfo.Type == REG_QWORD &&
                keyInfo.DataLength == sizeof(ULONG64))
            {
                *encodedSecurity = *(PULONG64)keyInfo.Data;
            }

            RegCloseKey(hKey);
        }
    }

    bool Driver::Init() {
        ULONG64 encodedCodes, encodedSecurity;
        ReadStealthyRegistry(&encodedCodes, &encodedSecurity);

        RDWCode = (ULONG)(encodedCodes & 0xFFFF);
        SHACode = (ULONG)((encodedCodes >> 16) & 0xFFFF);
        FGACode = (ULONG)((encodedCodes >> 32) & 0xFFFF);
        CR3Code = (ULONG)((encodedCodes >> 48) & 0xFFFF);
        SecurityCode = encodedSecurity;

        NN_TRAIN_CODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8325, METHOD_BUFFERED, FILE_ANY_ACCESS);
        NN_PREDICT_CODE = CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8326, METHOD_BUFFERED, FILE_ANY_ACCESS);

        Sleep(rand() % 100 + 50);

        DriverHandle = CreateFileW(
            L"\\\\.\\{2b3ﬂim90bﬂ9}",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            0,
            NULL
        );

        return (DriverHandle != INVALID_HANDLE_VALUE);
    }

    INT32 Driver::find_process(LPCTSTR process_name) {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name)) {
                    CloseHandle(hsnap);
                    ProcessId = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }

        CloseHandle(hsnap);
        return 0;
    }

    uintptr_t Driver::get_BaseAddress() {
        uintptr_t image_address = 0;
        struct {
            INT32 security;
            INT32 process_id;
            ULONGLONG* address;
        } arguments;

        arguments.security = SecurityCode;
        arguments.process_id = ProcessId;
        arguments.address = (ULONGLONG*)&image_address;

        DeviceIoControl(DriverHandle, SHACode, &arguments, sizeof(arguments),
            nullptr, 0, nullptr, nullptr);

        return image_address;
    }

    bool Driver::TrainNeuralNetwork(float* inputs, float* targets, int numSamples) {
        NNTrainRequest req;
        req.Security = SecurityCode;
        req.Inputs = inputs;
        req.Targets = targets;
        req.NumSamples = numSamples;

        DWORD bytesReturned;
        return DeviceIoControl(DriverHandle,
            NN_TRAIN_CODE,
            &req,
            sizeof(req),
            nullptr,
            0,
            &bytesReturned,
            nullptr);
    }

    bool Driver::PredictWithNeuralNetwork(float* inputs, float* outputs) {
        NNPredictRequest req;
        req.Security = SecurityCode;
        req.Inputs = inputs;
        req.Outputs = outputs;

        DWORD bytesReturned;
        return DeviceIoControl(DriverHandle,
            NN_PREDICT_CODE,
            &req,
            sizeof(req),
            nullptr,
            0,
            &bytesReturned,
            nullptr);
    }

    bool Driver::ReadVirtual(ULONGLONG address, PVOID buffer, SIZE_T size) {
        _rw arguments = { 0 };
        arguments.security = SecurityCode;
        arguments.process_id = ProcessId;
        arguments.address = address;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.write = FALSE;

        DWORD bytes;
        return DeviceIoControl(DriverHandle, RDWCode, &arguments, sizeof(arguments),
            nullptr, 0, &bytes, nullptr);
    }

    bool Driver::WriteVirtual(ULONGLONG address, PVOID buffer, SIZE_T size) {
        _rw arguments = { 0 };
        arguments.security = SecurityCode;
        arguments.process_id = ProcessId;
        arguments.address = address;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.write = TRUE;

        DWORD bytes;
        return DeviceIoControl(DriverHandle, RDWCode, &arguments, sizeof(arguments),
            nullptr, 0, &bytes, nullptr);
    }

    bool Driver::ReadPhysical(ULONGLONG physicalAddress, PVOID buffer, SIZE_T size) {
        _rw arguments = { 0 };
        arguments.security = SecurityCode;
        arguments.address = physicalAddress;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.write = FALSE;

        DWORD bytes;
        return DeviceIoControl(DriverHandle, CR3Code, &arguments, sizeof(arguments),
            nullptr, 0, &bytes, nullptr);
    }

    bool Driver::WritePhysical(ULONGLONG physicalAddress, PVOID buffer, SIZE_T size) {
        _rw arguments = { 0 };
        arguments.security = SecurityCode;
        arguments.address = physicalAddress;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.write = TRUE;

        DWORD bytes;
        return DeviceIoControl(DriverHandle, CR3Code, &arguments, sizeof(arguments),
            nullptr, 0, &bytes, nullptr);
    }

    std::vector<uint64_t> Driver::ScanPattern(const char* pattern, const char* mask,
        uint64_t startAddress, uint64_t endAddress, bool firstMatch) {
        std::vector<uint64_t> results;
        if (!pattern || !mask) return results;

        struct ScanRequest {
            uint64_t startAddress;
            uint64_t endAddress;
            uint8_t pattern[256];
            uint8_t mask[256];
            uint32_t patternSize;
            bool firstMatchOnly;
        } request;

        request.startAddress = startAddress ? startAddress : BaseAddress;
        request.endAddress = endAddress ? endAddress : (BaseAddress + 0x7FFFFFFF);
        request.patternSize = static_cast<uint32_t>(strlen(mask));
        request.firstMatchOnly = firstMatch;

        for (uint32_t i = 0; i < request.patternSize && i < 256; i++) {
            if (mask[i] == 'x') {
                request.pattern[i] = static_cast<uint8_t>(pattern[i]);
                request.mask[i] = 0xFF;
            }
            else {
                request.pattern[i] = 0;
                request.mask[i] = 0;
            }
        }

        const uint32_t CHUNK_SIZE = 0x10000;
        std::vector<uint8_t> buffer(CHUNK_SIZE);
        uint64_t currentAddress = request.startAddress;

        while (currentAddress < request.endAddress) {
            _rw arguments = { 0 };
            arguments.security = SecurityCode;
            arguments.process_id = ProcessId;
            arguments.address = currentAddress;
            arguments.buffer = (ULONGLONG)buffer.data();
            arguments.size = CHUNK_SIZE;
            arguments.write = FALSE;

            if (DeviceIoControl(DriverHandle, RDWCode, &arguments, sizeof(arguments),
                nullptr, 0, nullptr, nullptr)) {

                for (uint32_t i = 0; i < CHUNK_SIZE - request.patternSize; i++) {
                    bool found = true;
                    for (uint32_t j = 0; j < request.patternSize; j++) {
                        if (request.mask[j] && buffer[i + j] != request.pattern[j]) {
                            found = false;
                            break;
                        }
                    }

                    if (found) {
                        results.push_back(currentAddress + i);
                        if (request.firstMatchOnly) return results;
                        RandomizeAccessPattern();
                    }
                }
            }

            currentAddress += CHUNK_SIZE;

            if (results.size() > 0 && results.size() % 10 == 0) {
                Sleep(rand() % 50 + 10);
            }
        }

        return results;
    }

    std::vector<uint8_t> Driver::PatternToBytes(const char* pattern) {
        std::vector<uint8_t> bytes;
        char* start = const_cast<char*>(pattern);
        char* end = start + strlen(pattern);

        for (char* current = start; current < end; ++current) {
            if (*current == '?') {
                ++current;
                if (*current == '?') ++current;
                bytes.push_back(0);
            }
            else {
                bytes.push_back(static_cast<uint8_t>(strtoul(current, &current, 16)));
            }
        }
        return bytes;
    }

    bool Driver::ProtectMemoryRegion(uint64_t address, size_t size, DWORD protection) {
        // Implementation placeholder
        return true;
    }

    std::vector<MemoryRegion> Driver::GetProcessMemoryMap() {
        std::vector<MemoryRegion> regions;
        // Implementation placeholder
        return regions;
    }

    void Driver::RandomizeAccessPattern() {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> delay(10, 50);
        Sleep(delay(gen));
    }

    bool Driver::IsDriverHealthy() {
        return DriverHandle != INVALID_HANDLE_VALUE;
    }

} // namespace mem