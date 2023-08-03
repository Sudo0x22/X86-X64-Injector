#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

#include <cstdio>
#include <string>

std::string GetErrorCodeDescription(DWORD err);
DWORD SetPrivilege(HANDLE hToken, LPCTSTR lpszPrivilege, BOOL bEnablePrivilege);
void GetDebugPrivilege();

int GetProcessBitness(HANDLE process);

#define GetLastErrorCodeDescription() GetErrorCodeDescription(GetLastError())
#define GetLastErrorCodeDescriptionCstr() GetErrorCodeDescription(GetLastError()).c_str()