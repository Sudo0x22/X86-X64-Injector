#pragma once
#include<Windows.h>
#include<TlHelp32.h>
#include<string>
#include<chrono>
#include<filesystem>
#include<fstream>
#include<sstream>
#include<thread>
#include<iostream>

#define status_success 1
#define status_error 0

typedef struct _SYSTEM_MEMORY
{
	HMODULE hModule;
	FARPROC hModuleProcAddr;
	LPVOID hBaseAddress;
	HANDLE hRemoteHandle;
	SIZE_T hSize;
} SYSTEM_MEMORY, * PSYSTEM_MEMORY;

typedef struct _SYSTEM_PROCESS
{
	DWORD hProcessId;
	HANDLE hTargetProc;
	LPVOID hProcessAddress;
	HANDLE hOpenProcess;
	SIZE_T hProcSize;
};

class Memory
{
public:
	BOOL DoesPathExist(const std::string& file_path) {
		struct stat buffer;
		return (stat(file_path.c_str(), &buffer) == FALSE);
	}
}; Memory* pMemory = new Memory();