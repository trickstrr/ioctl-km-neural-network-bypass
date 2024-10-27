#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
uintptr_t virtualaddy;

#define RDWCode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8321, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define SHACode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8322, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define FGACode CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8323, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define CR3Code CTL_CODE(FILE_DEVICE_UNKNOWN, 0x8324, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define Securitycode 0x85F8AC8

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

namespace mem {
	HANDLE DriverHandle;
	INT32 ProcessIdentifier;

	bool Init() {
		DriverHandle = CreateFileW((L"\\\\.\\\{01922c515ad17d}"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!DriverHandle || (DriverHandle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void ReadPhysical(PVOID address, PVOID buffer, DWORD size) {
		_rw arguments = { 0 };

		arguments.security = Securitycode;
		arguments.address = (ULONGLONG)address;
		arguments.buffer = (ULONGLONG)buffer;
		arguments.size = size;
		arguments.process_id = ProcessIdentifier;
		arguments.write = FALSE;

		DeviceIoControl(DriverHandle, RDWCode, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	uintptr_t GetBaseAddress() {
		uintptr_t image_address = { NULL };
		_ba arguments = { NULL };

		arguments.security = Securitycode;
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
	t1drv::ReadPhysical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

bool IsValid(const uint64_t adress)
{
	if (adress <= 0x400000 || adress == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(adress) == nullptr || adress >
		0x7FFFFFFFFFFFFFFF) {
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
	return true; // you can add additional checks to verify successful reads
}

template<typename T>
bool ReadArray2(uint64_t address, T* out, size_t len)
{
	if (!t1drv::DriverHandle || t1drv::DriverHandle == INVALID_HANDLE_VALUE)
	{
		if (!t1drv::Init())
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
