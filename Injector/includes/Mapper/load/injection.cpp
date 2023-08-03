#include "injection.h"
#include <cstdio>
#include"../../secuirty/global.h"

#if _DEBUG
#if _WIN64
extern "C" void __CheckForDebuggerJustMyCode(char*);
#else
extern "C" void __fastcall __CheckForDebuggerJustMyCode(int);
#endif
#endif

void LoadLibraryInject(const char* dllPath, DWORD pid)
{
	HANDLE process = 0, thread = 0;
	DWORD exitCode = 0;

	// open the process
	////printf(x"[*] opening process with pid %d...\n", pid);
	process = __safecall(OpenProcess).get()(PROCESS_ALL_ACCESS, 0, pid);
	if (!process || process == INVALID_HANDLE_VALUE)
	{
		//printf(xorstr_("\t[-] OpenProcess failed: %s\n"), GetLastErrorCodeDescriptionCstr());
		return;
	}

	// allocate some memory
	////printf("[*] allocating memory in process...\n");
	void* loc = __safecall(VirtualAllocEx).get()(process, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!loc)
	{
		////printf("\t[-] VirtualAllocEx failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// write the dll path
	////printf("[*] writing dll path into memory...\n");
	if (__safecall(WriteProcessMemory).get()(process, loc, dllPath, strlen(dllPath) + 1, 0) == 0)
	{
		////printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// create remote thread
	////printf("[*] creating remote thread...\n");
	thread = __safecall(CreateRemoteThread).get()(process, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);
	if (!thread)
	{
		////printf("\t[-] CreateRemoteThread failed: %s\n", GetLastErrorCodeDescriptionCstr());
		goto cleanup;
	}

	// wait for it to finish
	//printf("[*] Loading DLL...\n");
	__safecall(WaitForSingleObject).get()(thread, INFINITE);

	if (!__safecall(GetExitCodeThread).get()(thread, &exitCode))
	{
		////puts("\t[-] failed to get exit code of injection thread");
	}

	// if LoadLibrary returns 0 (NULL), then it failed to load the module
	if (exitCode == 0)
	{
		//puts("\t[-] failed :(");
	}
	else
	{
		//puts("\t[+] success :)");
	}

cleanup:
	if (process)
	{
		__safecall(CloseHandle).get()(process);
	}
	if (thread)
	{
		__safecall(CloseHandle).get()(thread);
	}
}

void ManualMappingInject(const char* dllPath, DWORD pid)
{
	////printf("[*] opening process with pid %d...\n", pid);
	HANDLE process = __safecall(OpenProcess).get()(PROCESS_ALL_ACCESS, 0, pid);
	if (!process)
	{
		////printf("\t[-] OpenProcess failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

#pragma region get dll from disk

	////puts("[*] loading dll from disk");
	if (__safecall(GetFileAttributesA).get()(dllPath) == INVALID_FILE_ATTRIBUTES)
	{
		////printf("\t[-] GetFileAttributes failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	HANDLE file = __safecall(CreateFileA).get()(dllPath, GENERIC_READ, 0, 0, OPEN_EXISTING, 0, 0);
	if (file == INVALID_HANDLE_VALUE)
	{
		////printf("\t[-] CreateFile failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	DWORD fileSize = __safecall(GetFileSize).get()(file, 0);
	// the file headers are on the first page
	// so if the file the file is smaller than one page,
	// it can't possibly be a valid PE file.
	if (fileSize < 0x1000)
	{
		////puts("\t[-] invalid file: headers less than 4096 bytes");
		__safecall(CloseHandle).get()(file);
		return;
	}

	BYTE* srcData = (BYTE*)__safecall(VirtualAlloc).get()(0, fileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!srcData)
	{
		////printf("\t[-] VirtualAlloc failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	if (!__safecall(ReadFile).get()(file, srcData, fileSize, 0, 0))
	{
		////printf("\t[-] ReadFile failed: %s\n", GetLastErrorCodeDescriptionCstr());
		return;
	}

	__safecall(CloseHandle).get()(file);

#pragma endregion

#pragma region validate dll

	// validate image (check magic number)
	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(srcData);
	if (dosHeader->e_magic != 0x5A4D)
	{
		////puts("\t[-] invalid PE header");
		__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);
		return;
	}

	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(srcData + dosHeader->e_lfanew);
	IMAGE_OPTIONAL_HEADER* optHeader = &ntHeader->OptionalHeader;
	IMAGE_FILE_HEADER* fileHeader = &ntHeader->FileHeader;

	// ensure process and image bitness are same
	int processBitness = GetProcessBitness(process);
	if (!((fileHeader->Machine == IMAGE_FILE_MACHINE_AMD64 && processBitness == 64) ||
		(fileHeader->Machine == IMAGE_FILE_MACHINE_I386 && processBitness == 32)))
	{
		////puts("\t[-] process and image architectures do not match");
		__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);
		return;
	}

	// validate platform
	if (fileHeader->Machine !=
#ifdef _WIN64
		// should be x64 image
		IMAGE_FILE_MACHINE_AMD64)
#else
		// should be x86 image
		IMAGE_FILE_MACHINE_I386)
#endif
	{
		////puts("\t[-] invalid architecture");
		__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);
		return;
	}

#pragma endregion

#pragma region writing dll into process

	////puts("[*] mapping dll into target process");
	// allocate memory in the target process
	// use the preferred base address of the image if possible
	BYTE* dstData = (BYTE*)__safecall(VirtualAllocEx).get()(process, (void*)optHeader->ImageBase, optHeader->SizeOfImage,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!dstData)
	{
		////printf("\t[-] VirtualAllocEx (1 of 2) failed: %s\n", GetLastErrorCodeDescriptionCstr());
		// try again, not providing an image base
		dstData = (BYTE*)__safecall(VirtualAllocEx).get()(process, 0, optHeader->SizeOfImage,
			MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
		if (!dstData)
		{
			////printf("\t[-] VirtualAllocEx (2 of 2) failed: %s\n", GetLastErrorCodeDescriptionCstr());
			__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);
			return;
		}
	}

	ManualMappingInfo mmi = {};
	mmi.LoadLibraryA = __safecall(LoadLibraryA).get();
	mmi.GetProcAddress = reinterpret_cast<GetProcAddressSignature>(__safecall(GetProcAddress).get());

	// map sections into memory
	////puts("\t[*] mapping sections into memory");
	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (int i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader)
	{
		if (sectionHeader->SizeOfRawData)
		{
			if (__safecall(WriteProcessMemory).get()(process, dstData + sectionHeader->VirtualAddress,
				srcData + sectionHeader->PointerToRawData, sectionHeader->SizeOfRawData, 0))
			{
				////printf("\t\t[+] mapped %s\n", sectionHeader->Name);
			}
			else
			{
				////printf("\t\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
				__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);
				__safecall(VirtualFreeEx).get()(process, dstData, 0, MEM_RELEASE);
				return;
			}
		}
	}

	// copy the info into the first few bytes of the headers.
	// we don't need these bytes, and this saves us from needing
	// to allocate more memory in the target process for this write.
	*reinterpret_cast<ManualMappingInfo*>(srcData) = mmi;

	// write headers into memory
	if (!__safecall(WriteProcessMemory).get()(process, dstData, srcData, 0x1000, 0))
	{
		////printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		__safecall(VirtualFreeEx).get()(process, dstData, 0, MEM_RELEASE);
		return;
	}

	__safecall(VirtualFree).get()(srcData, 0, MEM_RELEASE);

#pragma endregion

#pragma region loader shellcode

	BYTE* loader = (BYTE*)Loader;

#pragma region fixing shellcode

#if _DEBUG
	////puts("[*] debug build only: resolving shellcode address");
	if (loader[0] == 0xE9)
	{
		// this address is actually a stub, find the actual address pls
		////printf("\t[*] located stub at 0x%p\n", loader);
		BYTE* nextInstruction = loader + 1 + 4;
		INT32 offset = loader[1] + (loader[2] << 8) + (loader[3] << 16) + (loader[4] << 24);
		loader = nextInstruction + offset;
		////printf("\t[*] found shellcode at 0x%p\n", loader);
	}

	////puts("[*] debug build only: patching function prologue");
	for (int i = 0; i < 0x40; ++i)
	{
		BYTE opcode = loader[i];
		// search for a call near instruction
		// opcode 0xE8
		if (opcode == 0xE8)
		{
			////printf("\t[*] found a CALL NEAR instruction at 0x%p\n", &loader[i]);
			// operand is 4 bytes
			BYTE* nextInstruction = &loader[i] + 1 + 4;
			INT32 offset = loader[i + 1] + (loader[i + 2] << 8) + (loader[i + 3] << 16) + (loader[i + 4] << 24);
			void* dst = nextInstruction + offset;
			if (dst == (void*)__CheckForDebuggerJustMyCode)
			{
				////printf("\t\t[*] instruction calls __CheckForDebuggerJustMyCode (0x%p)\n", dst);
				DWORD old;
				VirtualProtect(Loader, 0x1000, PAGE_EXECUTE_READWRITE, &old);

				// we have found a call to __CheckForDebuggerJustMyCode().
				// this won't work when injected, as the function likely
				// isn't defined in the code segment of the target process,
				// and almost definitely won't be at the same relative offset.
				// so, replace the function call with NOPs (0x90).
				loader[i++] = 0x90;
				loader[i++] = 0x90;
				loader[i++] = 0x90;
				loader[i++] = 0x90;
				loader[i++] = 0x90;

				VirtualProtect(Loader, 0x1000, old, &old);
				////puts("\t\t[+] patched with NOPs");
				break;
			}
		}
	}
#endif

#pragma endregion

#pragma region writing shellcode

	////puts("[*] writing loader shellcode into target process");
	// allocate one page of memory for the shellcode
	size_t shellcodeSize = 0x1000;
	void* shellcode = __safecall(VirtualAllocEx).get()(process, 0, shellcodeSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!shellcode)
	{
		//printf("\t[-] VirtualAllocEx failed: %s\n", GetLastErrorCodeDescriptionCstr());
		__safecall(VirtualFreeEx).get()(process, dstData, 0, MEM_RELEASE);
		return;
	}

	// write Loader shellcode into process memory (plus some extra, probably)
	if (!__safecall(WriteProcessMemory).get()(process, shellcode, loader, shellcodeSize, 0))
	{
		//printf("\t[-] WriteProcessMemory failed: %s\n", GetLastErrorCodeDescriptionCstr());
		__safecall(VirtualFreeEx).get()(process, dstData, 0, MEM_RELEASE);
		__safecall(VirtualFreeEx).get()(process, shellcode, 0, MEM_RELEASE);
		return;
	}

#pragma endregion

#pragma endregion

#pragma region create remote thread

	//puts("[*] creating remote thread in target process");
	HANDLE remoteThread = __safecall(CreateRemoteThread).get()(process, 0, 0,
		// our loader technically has a different signature,
		// but this is just so we dont need to do a bunch
		// of casting. this way, the values are casted for us (in effect)
#if TARGET_SELF
		// if we are targeting our own process (intended for debug builds)
		// then we can just call the function normally, and it should work fine.
		// this was purely for when debugging the Loader function.
		reinterpret_cast<LPTHREAD_START_ROUTINE>(Loader),
#else
		reinterpret_cast<LPTHREAD_START_ROUTINE>(shellcode),
#endif
		dstData, 0, 0);
	if (!remoteThread || remoteThread == INVALID_HANDLE_VALUE)
	{
		//printf("\t[-] CreateRemoteThread failed: %s\n", GetLastErrorCodeDescriptionCstr());
		__safecall(VirtualFreeEx).get()(process, dstData, 0, MEM_RELEASE);
		__safecall(VirtualFreeEx).get()(process, shellcode, 0, MEM_RELEASE);
		return;
	}

#pragma endregion

#pragma region wait for loader, display success/error messages

	//puts("[*] waiting for loader to finish");
	__safecall(WaitForSingleObject).get()(remoteThread, INFINITE);

	DWORD loaderExitCode = -1;
	if (__safecall(GetExitCodeThread).get()(remoteThread, &loaderExitCode))
	{
		switch (loaderExitCode)
		{
		case LOADER_SUCCESS:
			//puts("\t[+] loader: success");
			break;
		case LOADER_INVALID_ARGUMENT:
			//puts("\t[-] loader: invalid argument");
			break;
		case LOADER_RELOCATION_FAILED:
			//puts("\t[-] loader: relocation failed");
			break;
		case LOADER_IMPORTS_FAILED:
			//puts("\t[-] loader: imports failed");
			break;
		case LOADER_DLLMAIN_FAILED:
			//puts("\t[-] loader: DllMain failed");
			break;
		default:
			//printf("\t[-] loader: unexpected exit code 0x%X\n", loaderExitCode);
			break;
		}
	}
	else
	{
		//puts("\t[-] couldn't get loader exit code");
	}

#pragma endregion

	__safecall(CloseHandle).get()(remoteThread);
	__safecall(VirtualFreeEx).get()(process, shellcode, 0, MEM_RELEASE);
}

/* Loader
* this will be written into the target process (i.e. as shellcode)
* it is responsible for:
*		- relocation
*		- resolving imports
*		- calling TLS callbacks
*		- calling DllMain
*/
DWORD WINAPI Loader(ManualMappingInfo* info)
{
	if (!info)
		return LOADER_INVALID_ARGUMENT;

	// the info struct is located at the image base,
	// overwriting the first few bytes of the PE headers.
	BYTE* imageBase = reinterpret_cast<BYTE*>(info);

	// because we only overwrote the very beginning of the headers, should still be able to find the location of the optional header
	IMAGE_OPTIONAL_HEADER* optionalHeader = &reinterpret_cast<IMAGE_NT_HEADERS*>(
		imageBase + reinterpret_cast<IMAGE_DOS_HEADER*>(imageBase)->e_lfanew)->OptionalHeader;

#pragma region relocation

	BYTE* locationDelta = imageBase - optionalHeader->ImageBase;
	if (locationDelta)
	{
		if (!optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
			return LOADER_RELOCATION_FAILED;
		IMAGE_BASE_RELOCATION* relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
		while (relocData->VirtualAddress)
		{
			int numEntries = (relocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* relativeInfo = reinterpret_cast<WORD*>(relocData + 1);

			// apply patches at all entries
			for (int i = 0; i < numEntries; ++i, ++relativeInfo)
			{
				// type is given by the high 4 bits
				BYTE relocationType = (*relativeInfo >> 12);
				if (relocationType ==
#ifdef _WIN64
					IMAGE_REL_BASED_DIR64
#else
					IMAGE_REL_BASED_HIGHLOW
#endif
					)
				{
					// offset is given by the low 12 bits
					int patchOffset = *relativeInfo & 0xFFF;
					UINT_PTR* patch = reinterpret_cast<UINT_PTR*>(imageBase +
						relocData->VirtualAddress + patchOffset);
					*patch += reinterpret_cast<UINT_PTR>(locationDelta);
				}
			}

			// advance to next base relocation data block
			relocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(
				reinterpret_cast<BYTE*>(relocData) + relocData->SizeOfBlock);
		}
	}

#pragma endregion

#pragma region resolve imports

	if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
	{
		IMAGE_IMPORT_DESCRIPTOR* importDesc = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
		for (; importDesc->Name; ++importDesc)
		{
			char* importedModule = reinterpret_cast<char*>(imageBase + importDesc->Name);
			HINSTANCE module = info->LoadLibraryA(importedModule);

			if (!module)
			{
				// LoadLibraryA failed
				return LOADER_IMPORTS_FAILED;
			}

			ULONG_PTR* thunkRef = reinterpret_cast<ULONG_PTR*>(imageBase + importDesc->OriginalFirstThunk);
			ULONG_PTR* funcRef = reinterpret_cast<ULONG_PTR*>(imageBase + importDesc->FirstThunk);

			if (!thunkRef)
				thunkRef = funcRef;

			for (; *thunkRef; ++thunkRef, ++funcRef)
			{
				if (IMAGE_SNAP_BY_ORDINAL(*thunkRef))
				{
					*funcRef = info->GetProcAddress(module, reinterpret_cast<char*>(*thunkRef & 0xFFFF));
				}
				else
				{
					// import by name
					IMAGE_IMPORT_BY_NAME* import = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(imageBase + (*thunkRef));
					*funcRef = info->GetProcAddress(module, import->Name);
				}
				if (!(*funcRef))
				{
					// GetProcAddress failed
					return LOADER_IMPORTS_FAILED;
				}
			}
		}
	}

#pragma endregion

#pragma region tls callbacks

	if (optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
	{
		IMAGE_TLS_DIRECTORY* tls = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(
			imageBase + optionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
		PIMAGE_TLS_CALLBACK* callback = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(tls->AddressOfCallBacks);
		for (; callback && *callback; ++callback)
			// if a callback causes issues, there isn't really anything we can do
			(*callback)(imageBase, DLL_PROCESS_ATTACH, 0);
	}

#pragma endregion

#pragma region dllMain

	DllEntryPointSignature dllMain = reinterpret_cast<DllEntryPointSignature>(imageBase + optionalHeader->AddressOfEntryPoint);
	if (!dllMain(imageBase, DLL_PROCESS_ATTACH, (void*)0xDEADBEEF))
	{
		return LOADER_DLLMAIN_FAILED;
	}

#pragma endregion

	return LOADER_SUCCESS;
}