#pragma once
#include"../memory/memory.h"
#include"../spoofer/spoofer.hpp"
#include"../secuirty/global.h"

class WinApi
{
public:
	HANDLE WINAPI CreateSnapShot(DWORD dwFlags, DWORD dwProcId) {
		return SpoofReturn(__safecall(CreateToolhelp32Snapshot).get(), dwFlags, dwProcId);
	}
public:
	BOOL WINAPI ProcFirst(HANDLE ProcSnap, LPPROCESSENTRY32 ProcEntry) {
		return SpoofReturn(__safecall(Process32First).get(), ProcSnap, ProcEntry);
	}
	BOOL WINAPI ProcNext(HANDLE ProcSnap, LPPROCESSENTRY32 ProcEntry) {
		return SpoofReturn(__safecall(Process32Next).get(), ProcSnap, ProcEntry);
	}
public:
	BOOL WINAPI CloseHandleNew(HANDLE hHandle) {
		return SpoofReturn(__safecall(CloseHandle).get(), hHandle);
	}
	INT WINAPI StrCmp(LPCSTR First, LPCSTR Second) {
		return SpoofReturn(__safecall(strcmp).get(), First, Second);
	}
	VOID WINAPI NtSleep(DWORD time) {
		return SpoofReturn(__safecall(Sleep).get(), time);
	}
public:

}; WinApi* pWinApi = new WinApi();

class Utils
{
public:
	LPVOID WINAPI GetProcessAddress(std::string process_image,
		DWORD dwFlags, DWORD dwProcId)
	{
		PROCESSENTRY32 ProcEntry = { 0 };
		ProcEntry.dwSize = sizeof(PROCESSENTRY32);
		LPVOID ProcSnap = pWinApi->CreateSnapShot(dwFlags, dwProcId);

		if (ProcSnap == INVALID_HANDLE_VALUE)
			return nullptr;

		if (pWinApi->ProcFirst(ProcSnap, &ProcEntry) == FALSE)
			return nullptr;

		while (pWinApi->ProcNext(ProcSnap, &ProcEntry))
		{
			if (!pWinApi->StrCmp(ProcEntry.szExeFile, process_image.c_str())) {
				return (LPVOID)ProcEntry.th32ProcessID;
				pWinApi->CloseHandleNew(ProcSnap);
			}
		}
		
		pWinApi->CloseHandleNew(ProcSnap);
		return (LPVOID)dwProcId;
	}
}; Utils* pUtils = new Utils();

class Windows 
{
public:
	NTSTATUS WINAPI PrintStatus(LPCSTR Msg) {
		typedef LPCSTR(WINAPI* print_status)(LPCSTR);
		print_status print_msg = reinterpret_cast<print_status>(printf(Msg));
		return status_success;
	}
	NTSTATUS WINAPI SleepProc(DWORD Time) {
		pWinApi->NtSleep(Time);
		return status_success;
	}
	NTSTATUS WINAPI Exit(INT exit_code) {
		exit(exit_code);
		return status_success;
	}
}; Windows* pWindows = new Windows();