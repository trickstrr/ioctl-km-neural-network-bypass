#pragma once
#include <Windows.h>
#include <timeapi.h>
#include <vector>
#include <cstdint>
#include <TlHelp32.h>
#include <string>
#include "driver.h"

#pragma comment(lib, "ntdll.lib")

#define REG_KEY_PATH L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options"
#define REG_VALUE_NAME L"DebuggerValue"


typedef enum _KEY_VALUE_INFORMATION_CLASS {
    KeyValueBasicInformation = 0,
    KeyValueFullInformation,
    KeyValuePartialInformation,
    KeyValueFullInformationAlign64,
    KeyValuePartialInformationAlign64,
    KeyValueLayerInformation,
    MaxKeyValueInfoClass
} KEY_VALUE_INFORMATION_CLASS;

typedef struct _KEY_VALUE_PARTIAL_INFORMATION {
    ULONG TitleIndex;
    ULONG Type;
    ULONG DataLength;
    UCHAR Data[1];
} KEY_VALUE_PARTIAL_INFORMATION, * PKEY_VALUE_PARTIAL_INFORMATION;

typedef NTSTATUS(NTAPI* PNtQueryValueKey)(
    HANDLE KeyHandle,
    PUNICODE_STRING ValueName,
    KEY_VALUE_INFORMATION_CLASS KeyValueInformationClass,
    PVOID KeyValueInformation,
    ULONG Length,
    PULONG ResultLength
    );


typedef VOID(NTAPI* PRtlInitUnicodeString)(
    PUNICODE_STRING DestinationString,
    PCWSTR SourceString
    );

namespace driver_status {

    class DriverHealth {
    public:
        static constexpr DWORD TIMING_CHECK_INTERVAL = 1000;

        struct HealthMetrics {
            LARGE_INTEGER lastCheckTime;
            uint32_t failedOperations;
            uint32_t successfulOperations;
            uint32_t detectionAttempts;
            uint32_t anomalyCount;
            float healthScore;
            bool isCompromised;
        };

        explicit DriverHealth(mem::Driver* driver);
        bool IsDriverHealthy();
        void UpdateOperationStatus(bool success);
        HealthMetrics GetCurrentMetrics() const { return metrics; }

    private:
        mem::Driver* m_driver;
        HealthMetrics metrics;
        const std::vector<uint8_t> knownPatterns;

        static constexpr float MINIMUM_HEALTH_SCORE = 60.0f;
        static constexpr uint8_t OriginalDriverHash[32] = { 0 };

        bool ValidateDriverHandle();
        bool DetectAnalysisTools();
        bool ScanForAnalysisTools();
        bool VerifyDriverIntegrity();
        bool CalculateDriverHash(uint8_t* hash);
        float CalculateSuccessRate();
        bool PerformTimingChecks();
        void ApplyAntiDetectionMeasures();
        void UpdateHealthMetrics(const HealthMetrics& current);
        void LogHealthChange();
    };

    class StatusMonitor {
    public:
        explicit StatusMonitor(mem::Driver* driver);
        void Initialize();
        bool IsSystemHealthy();
        void ReportOperation(bool success);
        std::string GetStatusReport();

    private:
        mem::Driver* m_driver;
        DriverHealth m_health;
        LARGE_INTEGER m_lastCheck;
        bool m_initialized;
    };

} // namespace driver_status