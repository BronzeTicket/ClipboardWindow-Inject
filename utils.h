#pragma once
#include <windows.h>
#include "beacon.h"
#include "libc.h"

#define TH32CS_SNAPPROCESS	0x00000002
#define STATUS_SUCCESS	((NTSTATUS)0x00000000L) 

typedef struct tagPROCESSENTRY32
{
	DWORD   dwSize;
	DWORD   cntUsage;
	DWORD   th32ProcessID;          // this process
	ULONG_PTR th32DefaultHeapID;
	DWORD   th32ModuleID;           // associated exe
	DWORD   cntThreads;
	DWORD   th32ParentProcessID;    // this process's parent process
	LONG    pcPriClassBase;         // Base priority of process's threads
	DWORD   dwFlags;
	CHAR    szExeFile[MAX_PATH];    // Path

} PROCESSENTRY32, * LPPROCESSENTRY32;

typedef struct _UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;

} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES
{
	ULONG Length;
	HANDLE RootDirectory;
	PUNICODE_STRING ObjectName;
	ULONG Attributes;
	PVOID SecurityDescriptor;        // Points to type SECURITY_DESCRIPTOR
	PVOID SecurityQualityOfService;  // Points to type SECURITY_QUALITY_OF_SERVICE

} OBJECT_ATTRIBUTES, * POBJECT_ATTRIBUTES;

typedef enum _SECTION_INHERIT
{
	ViewShare = 1,
	ViewUnmap = 2

} SECTION_INHERIT;

typedef struct _IUnknown_t {
	// a pointer to virtual function table
	ULONG_PTR lpVtbl;
	// the virtual function table
	ULONG_PTR QueryInterface;
	ULONG_PTR AddRef;
	ULONG_PTR Release;       // executed for WM_DESTROYCLIPBOARD
} IUnknown_t;

DECLSPEC_IMPORT WINUSERAPI HWND WINAPI USER32$FindWindowExA(HWND, HWND, LPCSTR, LPCSTR);
DECLSPEC_IMPORT WINUSERAPI DWORD WINAPI USER32$GetWindowThreadProcessId(HWND, LPDWORD);
DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32First(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT BOOL WINAPI KERNEL32$Process32Next(HANDLE, LPPROCESSENTRY32);
DECLSPEC_IMPORT WINBASEAPI BOOL WINAPI KERNEL32$CloseHandle(HANDLE);

HWND FindTargetClipboardWindow(DWORD);