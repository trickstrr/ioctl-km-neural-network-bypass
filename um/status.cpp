#include "status.h"
#include <sstream>
#include <cmath>

namespace driver_status {

    DriverHealth::DriverHealth(mem::Driver* driver)
        : m_driver(driver),
        knownPatterns{
            0x48, 0x8B, 0x05,  // EAC common pattern
            0x48, 0x89, 0x5C,  // BE common pattern
            0x40, 0x53, 0x48   // Analysis tool pattern
        }
    {
        memset(&metrics, 0, sizeof(metrics));
        metrics.healthScore = 100.0f;
    }

    bool DriverHealth::VerifyDriverIntegrity() {
        uint8_t currentHash[32] = { 0 };
        if (!CalculateDriverHash(currentHash)) {
            return false;
        }

        Sleep(rand() % 50 + 10);

        for (int i = 0; i < 32; i++) {
            if (currentHash[i] != OriginalDriverHash[i]) {
                return false;
            }
        }

        return true;
    }

    bool DriverHealth::CalculateDriverHash(uint8_t* hash) {
        if (!m_driver || !hash) return false;

        uint32_t rolling_hash = 0x811C9DC5;
        uint8_t buffer[1024];

        for (size_t offset = 0; offset < 0x1000; offset += sizeof(buffer)) {
            if (!m_driver->ReadVirtual(offset, buffer, sizeof(buffer))) {
                return false;
            }

            for (size_t i = 0; i < sizeof(buffer); i++) {
                rolling_hash ^= buffer[i];
                rolling_hash *= 0x01000193;
            }
        }

        for (int i = 0; i < 32; i++) {
            hash[i] = (rolling_hash >> (i * 8)) & 0xFF;
        }

        return true;
    }

    bool DriverHealth::ValidateDriverHandle() {
        if (!m_driver || !m_driver->GetDriverHandle() || m_driver->GetDriverHandle() == INVALID_HANDLE_VALUE)
            return false;

        uint8_t testBuffer[4] = { 0 };
        return m_driver->ReadVirtual((ULONGLONG)GetModuleHandle(NULL), testBuffer, sizeof(testBuffer));
    }

    float DriverHealth::CalculateSuccessRate() {
        uint32_t total = metrics.successfulOperations + metrics.failedOperations;
        if (total == 0) return 1.0f;
        return static_cast<float>(metrics.successfulOperations) / static_cast<float>(total);
    }

    bool DriverHealth::PerformTimingChecks() {
        LARGE_INTEGER frequency, start, end;
        QueryPerformanceFrequency(&frequency);

        const int NUM_CHECKS = 5;
        double timings[NUM_CHECKS];

        for (int i = 0; i < NUM_CHECKS; i++) {
            QueryPerformanceCounter(&start);

            uint8_t testBuffer[4];
            m_driver->ReadVirtual(m_driver->BaseAddress, testBuffer, sizeof(testBuffer));

            QueryPerformanceCounter(&end);
            timings[i] = (end.QuadPart - start.QuadPart) * 1000000.0 / frequency.QuadPart;
            Sleep(rand() % 20 + 5);
        }

        double avg = 0.0;
        for (int i = 0; i < NUM_CHECKS; i++) {
            avg += timings[i];
        }
        avg /= NUM_CHECKS;

        return (avg > 1.0 && avg < 100.0);
    }

    void DriverHealth::ApplyAntiDetectionMeasures() {
        uint8_t dummy[16];
        for (int i = 0; i < 3; i++) {
            uint64_t randomAddr = m_driver->BaseAddress + (rand() % 0x1000);
            m_driver->ReadVirtual(randomAddr, dummy, sizeof(dummy));
            Sleep(rand() % 5 + 1);
        }

        timeBeginPeriod(1);
        Sleep(rand() % 3 + 1);
        timeEndPeriod(1);

        SetLastError(0);

        volatile uint8_t stack_buffer[32];
        for (int i = 0; i < 32; i++) {
            stack_buffer[i] = rand() % 256;
        }
    }

    bool DriverHealth::DetectAnalysisTools() {
        if (IsDebuggerPresent()) return true;

        BOOL remoteDebugger = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &remoteDebugger);
        if (remoteDebugger) return true;

        return ScanForAnalysisTools();
    }

    bool DriverHealth::ScanForAnalysisTools() {
        const wchar_t* knownTools[] = {
            L"x64dbg.exe", L"windbg.exe", L"ida64.exe",
            L"processhacker.exe", L"cheatengine-x86_64.exe"
        };

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;

        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(pe32);

        bool toolFound = false;
        if (Process32FirstW(snapshot, &pe32)) {
            do {
                for (const auto& tool : knownTools) {
                    if (_wcsicmp(pe32.szExeFile, tool) == 0) {
                        toolFound = true;
                        break;
                    }
                }
            } while (!toolFound && Process32NextW(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return toolFound;
    }

    void DriverHealth::UpdateHealthMetrics(const HealthMetrics& current) {
        const float alpha = 0.3f;
        metrics.healthScore = alpha * current.healthScore + (1.0f - alpha) * metrics.healthScore;
        metrics.detectionAttempts += current.detectionAttempts;
        metrics.anomalyCount += current.anomalyCount;
        metrics.lastCheckTime = current.lastCheckTime;
        metrics.isCompromised |= current.isCompromised;

        if (abs(metrics.healthScore - current.healthScore) > 20.0f) {
            LogHealthChange();
        }
    }

    void DriverHealth::LogHealthChange() {
        SYSTEMTIME st;
        GetSystemTime(&st);

        char logBuffer[256];
        snprintf(logBuffer, sizeof(logBuffer),
            "[%02d:%02d:%02d] Health Score: %.2f, Detections: %d, Anomalies: %d\n",
            st.wHour, st.wMinute, st.wSecond,
            metrics.healthScore,
            metrics.detectionAttempts,
            metrics.anomalyCount
        );

        OutputDebugStringA(logBuffer);
    }

    bool DriverHealth::IsDriverHealthy() {
        HealthMetrics currentMetrics = { 0 };
        QueryPerformanceCounter(&currentMetrics.lastCheckTime);

        if (!ValidateDriverHandle()) {
            currentMetrics.healthScore -= 30.0f;
            currentMetrics.isCompromised = true;
            UpdateHealthMetrics(currentMetrics);
            return false;
        }

        if (DetectAnalysisTools()) {
            currentMetrics.detectionAttempts++;
            currentMetrics.healthScore -= 20.0f;
        }

        if (!VerifyDriverIntegrity()) {
            currentMetrics.healthScore -= 25.0f;
            currentMetrics.isCompromised = true;
        }

        float successRate = CalculateSuccessRate();
        if (successRate < 0.8f) {
            currentMetrics.healthScore -= (1.0f - successRate) * 50.0f;
        }

        if (!PerformTimingChecks()) {
            currentMetrics.anomalyCount++;
            currentMetrics.healthScore -= 15.0f;
        }

        ApplyAntiDetectionMeasures();
        UpdateHealthMetrics(currentMetrics);

        return metrics.healthScore > MINIMUM_HEALTH_SCORE && !metrics.isCompromised;
    }

    void DriverHealth::UpdateOperationStatus(bool success) {
        if (success) {
            metrics.successfulOperations++;
        }
        else {
            metrics.failedOperations++;
        }
    }

    // StatusMonitor implementation
    StatusMonitor::StatusMonitor(mem::Driver* driver)
        : m_driver(driver),
        m_health(driver),
        m_initialized(false)
    {
        QueryPerformanceCounter(&m_lastCheck);
    }

    void StatusMonitor::Initialize() {
        if (!m_initialized) {
            m_initialized = m_health.IsDriverHealthy();
        }
    }

    bool StatusMonitor::IsSystemHealthy() {
        LARGE_INTEGER currentTime, frequency;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&currentTime);

        if ((currentTime.QuadPart - m_lastCheck.QuadPart) >
            (DriverHealth::TIMING_CHECK_INTERVAL * frequency.QuadPart / 1000)) {
            m_lastCheck = currentTime;
            return m_health.IsDriverHealthy();
        }

        return m_initialized;
    }

    void StatusMonitor::ReportOperation(bool success) {
        m_health.UpdateOperationStatus(success);
    }

    std::string StatusMonitor::GetStatusReport() {
        std::stringstream ss;
        auto metrics = m_health.GetCurrentMetrics();

        ss << "Driver Status Report:\n"
            << "Health Score: " << metrics.healthScore << "\n"
            << "Successful Operations: " << metrics.successfulOperations << "\n"
            << "Failed Operations: " << metrics.failedOperations << "\n"
            << "Detection Attempts: " << metrics.detectionAttempts << "\n"
            << "Anomaly Count: " << metrics.anomalyCount << "\n"
            << "System Status: " << (metrics.isCompromised ? "COMPROMISED" : "HEALTHY") << "\n";

        return ss.str();
    }

} 