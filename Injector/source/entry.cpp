#include"../includes/includes.h"

extern "C" { namespace strings
{
	std::string proc_image = "";
	std::string dll_path = "";
}}

NTSTATUS WINAPI main(LPVOID Buffer) {
	
	SetConsoleTitleA(__("X86/X64 Injector - Sudo0x22"));

	pWindows->PrintStatus(__("[ - LOGS - ] -> Enter Process Image: "));
	std::cin >> strings::proc_image;
	LPVOID ProcessAddress = pUtils->GetProcessAddress(strings::proc_image, TH32CS_SNAPPROCESS, 0);

	if (!ProcessAddress) {
		pWindows->PrintStatus(__("[ - DEBUG - ] -> Failed To Locate Process\n"));
		pWindows->SleepProc(5000);
		pWindows->Exit(1);
	}

	pWindows->PrintStatus(__("[ - LOGS - ] -> Process Found Enter Dll Path: "));
	std::cin >> strings::dll_path;
	BOOL DoesFileExist = pMemory->DoesPathExist(strings::dll_path);

	if (!DoesFileExist) {
		pWindows->PrintStatus(__("[ - DEBUG - ] -> File Not Found\n"));
		pWindows->SleepProc(5000);
		pWindows->Exit(1);
	}

	pWindows->PrintStatus(__("[ - LOGS - ] -> File Found Mapping Now\n"));
	ManualMappingInject(strings::dll_path.c_str(), (DWORD)ProcessAddress);
	pWindows->SleepProc(3000);

	pWindows->PrintStatus(__("[ - LOGS - ] -> Image Mapped Closing Now\n"));
	pWindows->SleepProc(3000);
	pWindows->Exit(0);

	return status_success;
}