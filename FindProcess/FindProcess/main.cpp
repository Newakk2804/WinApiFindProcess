#include <windows.h>
#include <psapi.h>
#include <iostream>
#include <vector>

void PrintExportedFunctions(HMODULE hModule) {
	if (!hModule) {
		std::cerr << "Invalid module!" << std::endl;
		return;
	}
	BYTE* baseAddress = reinterpret_cast<BYTE*>(hModule);
	PIMAGE_DOS_HEADER dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddress);

	if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
		std::cerr << "Invalid DOS header!" << std::endl;
		return;
	}

	PIMAGE_NT_HEADERS ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(baseAddress + dosHeader->e_lfanew);

	if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
		std::cerr << "Invalid NT header!" << std::endl;
		return;
	}

	if (ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size > 0) {
		PIMAGE_EXPORT_DIRECTORY exportDir = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(
			baseAddress + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

		DWORD* functionNames = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfNames);
		DWORD* functionAddresses = reinterpret_cast<DWORD*>(baseAddress + exportDir->AddressOfFunctions);
		WORD* functionOrdinals = reinterpret_cast<WORD*>(baseAddress + exportDir->AddressOfNameOrdinals);

		std::cout << "Export functions:\n";

		for (DWORD i = 0; i < exportDir->NumberOfNames; ++i) {
			const char* functionName = reinterpret_cast<const char*>(baseAddress + functionNames[i]);
			DWORD functionAddress = functionAddresses[functionOrdinals[i]];

			if (functionAddress) {
				std::cout << "  " << functionName << " - Address: " << (void*)(baseAddress + functionAddress) << std::endl;
			}
		}
	}
}

void PrintLoadedModulesAndFunctions(DWORD processID) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);

	if (!hProcess) {
		std::cerr << "Error open process! Error code: " << GetLastError() << std::endl;
		return;
	}

	HMODULE hMods[1024];
	DWORD cbNeeded;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
		DWORD moduleCount = cbNeeded / sizeof(HMODULE);
		for (DWORD i = 0; i < moduleCount; i++) {
			char moduleName[MAX_PATH];
			if (GetModuleFileNameExA(hProcess, hMods[i], moduleName, sizeof(moduleName))) {
				std::cout << "Modules: " << moduleName << std::endl;
				
				BYTE moduleBuffer[4096];
				SIZE_T bytesRead;
				if (ReadProcessMemory(hProcess, hMods[i], moduleBuffer, sizeof(moduleBuffer), &bytesRead)) {
					PrintExportedFunctions(reinterpret_cast<HMODULE>(moduleBuffer));
				}
				else {
					std::cerr << "Not reading memory module! Error code: " << GetLastError() << std::endl;
				}
			}
		}
	}
	else {
		std::cerr << "Not get modules! Error code: " << GetLastError() << std::endl;
	}
	CloseHandle(hProcess);
}

int main() {
	DWORD processID;
	std::cout << "Input ID proc: ";
	std::cin >> processID;

	PrintLoadedModulesAndFunctions(processID);

	return 0;
}