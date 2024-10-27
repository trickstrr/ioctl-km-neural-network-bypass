#pragma once

#include <Windows.h>
#include <winternl.h>
#include <TlHelp32.h>
#include <cstdint>

#pragma comment(lib, "ntdll.lib")

uintptr_t virtualaddy;

#define REG_KEY_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define REG_VALUE_NAME L"DebuggerValue"

#ifndef KEY_VALUE_INFORMATION_CLASS
typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;
#endif

#ifndef _KEY_VALUE_PARTIAL_INFORMATION
typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;
#endif

typedef NTSTATUS(NTAPI* PNtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
    );

typedef struct _rw {
    INT32 security;
    INT32 process_id;
    ULONGLONG address;
    ULONGLONG buffer;
    ULONGLONG size;
    BOOLEAN write;
} rw, * prw;

typedef struct _ba {
    INT32 security;
    INT32 process_id;
    ULONGLONG* address;
} ba, * pba;

typedef struct _ga {
    INT32 security;
    ULONGLONG* address;
} ga, * pga;

void ReadStealthyRegistry(ULONG64* encodedCodes, ULONG64* encodedSecurity)
{
    HKEY hKey;
    PNtQueryValueKey NtQueryValueKey = (PNtQueryValueKey)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryValueKey");

    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, REG_KEY_PATH, 0, KEY_READ, &hKey) == ERROR_SUCCESS)
    {
        UNICODE_STRING valueName;
        KEY_VALUE_PARTIAL_INFORMATION keyInfo;
        ULONG resultLength;

        RtlInitUnicodeString(&valueName, L"EncodedCodes");
        NTSTATUS status = NtQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &keyInfo, sizeof(keyInfo), &resultLength);
        if (NT_SUCCESS(status) && keyInfo.Type == REG_QWORD && keyInfo.DataLength == sizeof(ULONG64))
            *encodedCodes = *(PULONG64)keyInfo.Data;

        RtlInitUnicodeString(&valueName, L"EncodedSecurity");
        status = NtQueryValueKey(hKey, &valueName, KeyValuePartialInformation, &keyInfo, sizeof(keyInfo), &resultLength);
        if (NT_SUCCESS(status) && keyInfo.Type == REG_QWORD && keyInfo.DataLength == sizeof(ULONG64))
            *encodedSecurity = *(PULONG64)keyInfo.Data;

        RegCloseKey(hKey);
    }
}

namespace mem {
    HANDLE DriverHandle;
    INT32 ProcessIdentifier;
    ULONG RDWCode, SHACode, FGACode, CR3Code;
    ULONG64 Securitycode;

    bool Init() {
        ULONG64 encodedCodes, encodedSecurity;
        ReadStealthyRegistry(&encodedCodes, &encodedSecurity);

        RDWCode = (ULONG)(encodedCodes & 0xFFFF);
        SHACode = (ULONG)((encodedCodes >> 16) & 0xFFFF);
        FGACode = (ULONG)((encodedCodes >> 32) & 0xFFFF);
        CR3Code = (ULONG)((encodedCodes >> 48) & 0xFFFF);
        Securitycode = encodedSecurity;

        DriverHandle = CreateFileW(L"\\\\.\\{2b3ﬂim90bﬂ9}", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

        return (DriverHandle != INVALID_HANDLE_VALUE);
    }

    void ReadPhysical(PVOID address, PVOID buffer, DWORD size) {
        rw arguments = { 0 };

        arguments.security = (INT32)Securitycode;
        arguments.address = (ULONGLONG)address;
        arguments.buffer = (ULONGLONG)buffer;
        arguments.size = size;
        arguments.process_id = ProcessIdentifier;
        arguments.write = FALSE;

        DeviceIoControl(DriverHandle, RDWCode, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
    }

    uintptr_t GetBaseAddress() {
        uintptr_t image_address = { NULL };
        ba arguments = { NULL };

        arguments.security = (INT32)Securitycode;
        arguments.process_id = ProcessIdentifier;
        arguments.address = (ULONGLONG*)&image_address;

        DeviceIoControl(DriverHandle, SHACode, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

        return image_address;
    }

    INT32 find_process(LPCTSTR process_name) {
        PROCESSENTRY32 pt;
        HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        pt.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hsnap, &pt)) {
            do {
                if (!lstrcmpi(pt.szExeFile, process_name)) {
                    CloseHandle(hsnap);
                    ProcessIdentifier = pt.th32ProcessID;
                    return pt.th32ProcessID;
                }
            } while (Process32Next(hsnap, &pt));
        }
        CloseHandle(hsnap);

        return { NULL };
    }
}

template <typename T>
T read(uint64_t address) {
    T buffer{ };
    mem::ReadPhysical((PVOID)address, &buffer, sizeof(T));
    return buffer;
}

bool IsValid(const uint64_t address)
{
    if (address <= 0x400000 || address == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(address) == nullptr || address > 0x7FFFFFFFFFFFFFFF) {
        return false;
    }
    return true;
}

template<typename T>
bool ReadArray(uintptr_t address, T out[], size_t len)
{
    for (size_t i = 0; i < len; ++i)
    {
        out[i] = read<T>(address + i * sizeof(T));
    }
    return true;
}

template<typename T>
bool ReadArray2(uint64_t address, T* out, size_t len)
{
    if (!mem::DriverHandle || mem::DriverHandle == INVALID_HANDLE_VALUE)
    {
        if (!mem::Init())
        {
            return false;
        }
    }

    if (!out || len == 0)
    {
        return false;
    }

    for (size_t i = 0; i < len; ++i)
    {
        if (!IsValid(address + i * sizeof(T)))
        {
            return false;
        }

        out[i] = read<T>(address + i * sizeof(T));
    }
    return true;
}