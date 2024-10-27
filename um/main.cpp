#include <iostream>
#include "driver.h"

using namespace std;

auto main() -> void
{
	SetConsoleTitleA("usermode - Payson's ioctl base");
	if (!mem::Init()) {
		system("color 2");
		cout << "\n driver communications not initialized.\n";
	}

	mem::ProcessIdentifier = mem::find_process("FortniteClient-Win64-Shipping.exe");
	
	virtualaddy = mem::GetBaseAddress();

	cout << "Process BaseAddress -> " << virtualaddy << "\n";

	/*
	*
	* Example Handling
	*
	* 	read<__int64>(vaworld);
	*	read<uintptr_t>(pointer->uworld + offsets::gameinstance);
	* 
	*/

	cin.get();
}