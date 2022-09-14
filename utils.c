#include "utils.h"

VOID GetProcessName(DWORD dwPid, __out char* lpcszProcessName) {
	HANDLE hSnap = NULL;
	BOOL  fResult = FALSE;
	PROCESSENTRY32 pe32;

	hSnap = KERNEL32$CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnap != INVALID_HANDLE_VALUE) {
		pe32.dwSize = sizeof(PROCESSENTRY32);

		fResult = KERNEL32$Process32First(hSnap, &pe32);
		while (fResult) {
			if (pe32.th32ProcessID == dwPid) {
				mycopy(lpcszProcessName, pe32.szExeFile, mystrlen(pe32.szExeFile));
				break;
			}
			fResult = KERNEL32$Process32Next(hSnap, &pe32);
		}

		KERNEL32$CloseHandle(hSnap);
	}
	return;
}

HWND FindTargetClipboardWindow(DWORD dwTargetPid) {
	HWND  hwClipBoardWindow = NULL;
	DWORD dwPid;
	BeaconPrintf(CALLBACK_OUTPUT, "%-20s%-10sPROCESS\n", "HWND", "PID");
	BeaconPrintf(CALLBACK_OUTPUT, "*****************************************\n");
	for (;;) {
		hwClipBoardWindow = USER32$FindWindowExA(HWND_MESSAGE, hwClipBoardWindow, "CLIPBRDWNDCLASS", NULL);
		if (hwClipBoardWindow == NULL) break;

		USER32$GetWindowThreadProcessId(hwClipBoardWindow, &dwPid);
		char lpcszProcessName[260] = { 0 };
		GetProcessName(dwPid, lpcszProcessName);
		BeaconPrintf(CALLBACK_OUTPUT, "%-20p%-10i%s", hwClipBoardWindow, dwPid, lpcszProcessName);

		if (dwTargetPid == dwPid) {
			return hwClipBoardWindow;
		}
	}
	return NULL;
}