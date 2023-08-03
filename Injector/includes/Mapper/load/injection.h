#pragma once
#define TARGET_SELF 0
#include "Win32Helpers.h"

void LoadLibraryInject(const char* dllPath, DWORD procId);

void ManualMappingInject(const char* dllPath, DWORD pid);

using LoadLibraryASignature = HINSTANCE(WINAPI*)(const char* filename);
using GetProcAddressSignature = UINT_PTR(WINAPI*)(HINSTANCE module, const char* procName);
using DllEntryPointSignature = BOOL(WINAPI*)(void* dll, DWORD reason, void* reserved);

struct ManualMappingInfo
{
	// passing LoadLibraryA and GetProcAddress
	// like this only works because these
	// functions are in Kernel32.dll, which is
	// imported at same virtual address in
	// every process
	LoadLibraryASignature LoadLibraryA;
	GetProcAddressSignature GetProcAddress;
};

#define LOADER_SUCCESS				0
#define LOADER_INVALID_ARGUMENT		1
#define LOADER_RELOCATION_FAILED	2
#define LOADER_IMPORTS_FAILED		3
#define LOADER_DLLMAIN_FAILED		4

DWORD __stdcall Loader(ManualMappingInfo* info);
