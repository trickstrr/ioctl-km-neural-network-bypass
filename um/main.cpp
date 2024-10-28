#include <iostream>
#include "driver.h"
//#include "status.h"

mem::Driver driver;

// Pattern Scanner Usage example:

void FindPattern() {
   
    auto extResults = driver.ScanPattern(
        "\x48\x89\x5C\x24\x08\x48\x89\x74\x24\x10",  // Pattern
        "xxxxxxxxxx",                                  // Mask
        0x140000000,                                  // Start address
        0x150000000,                                  // End address
        true                                          // First match only
    );
}




int main() {
    SetConsoleTitleA("TrickSTRR NeuralNetwork Usermode");
  

    if (!driver.Init()) {
        std::cout << "\n driver communications not initialized.\n";
        return 1;
    }

    
    INT32 processId = driver.find_process("FortniteClient-Win64-Shipping.exe");
    if (processId == 0) {
        std::cout << "Process not found!\n";
        return 1;
    }

    // Get base address
    driver.BaseAddress = driver.get_BaseAddress();
    std::cout << "Base Address: " << std::hex << driver.BaseAddress << std::dec << std::endl;

    // Train neural network
    float inputs[] = { 1.0f, 0.0f, 1.0f };
    float targets[] = { 1.0f };
    driver.TrainNeuralNetwork(inputs, targets, 1);

    // Read memory with anti-detection
    auto value = driver.Read<int>(0x12345678);
    driver.RandomizeAccessPattern();

    // Pattern scanning
    auto addresses = driver.ScanPattern("\x48\x89\x5C", "xxx");

    return 0;
}