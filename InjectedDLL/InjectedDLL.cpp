#include "InjectedDLL.h"

#include <string>
#include <iostream>
#include <Windows.h>

//#define INJECTEDDLL extern "C" declspec(dllexport)

DWORD gFreqOffset = 0;

BOOL WINAPI myMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
	lpText = /*const_cast<LPCSTR>*/(lpText + (const char)"_Hack!");
	Beep(500, 500);
	return MessageBoxA(hWnd, lpText, lpCaption, uType);
}

BOOL WINAPI myMessageBoxW(HWND hWnd, LPCWSTR lpText, LPCWSTR lpCaption, UINT uType) {
	lpText = /*const_cast<LPCSTR>*/(lpText + (const WCHAR)"_Hack!");
	Beep(800, 800);
	return MessageBoxW(hWnd, lpText, lpCaption, uType);
}

// EasyHook will be looking for this export to support DLL injection. If not found then 
// DLL injection will fail.
extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO * inRemoteInfo);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo)
{
	
	//MessageBoxA(NULL, "INJECTED!", "CAPTION", 0);
	MessageBoxW(NULL, L"INJECTED!", L"CAPTION", 0);

	//std::cout << "Injected by process Id: " << inRemoteInfo->HostPID << "\n";
	//std::cout << "Passed in data size: " << inRemoteInfo->UserDataSize << "\n";
	//if (inRemoteInfo->UserDataSize == sizeof(DWORD))
	//{
	//	gFreqOffset = *reinterpret_cast<DWORD*>(inRemoteInfo->UserData);
	//	std::cout << "Adjusting Beep frequency by: " << gFreqOffset << "\n";
	//}

	// Perform hooking
	HOOK_TRACE_INFO hHookMessageBoxA = { NULL }; // keep track of our hook
	HOOK_TRACE_INFO hHookMessageBoxW = { NULL }; // keep track of our hook

	//std::cout << "\n";
	//std::cout << "Win32 Beep found at address: " << GetProcAddress(GetModuleHandle(TEXT("USER32.DLL")), "MessageBoxA") << "\n";

	// Install the hook
	NTSTATUS result1 = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("USER32.DLL")), "MessageBoxA"),
		myMessageBoxA,
		NULL,
		&hHookMessageBoxA);

	NTSTATUS result2 = LhInstallHook(
		GetProcAddress(GetModuleHandle(TEXT("USER32.DLL")), "MessageBoxW"),
		myMessageBoxW,
		NULL,
		&hHookMessageBoxW);

	if (FAILED(result2)) { MessageBoxW(NULL, L"FILED TO INSTALL HOOK!", L"CAPTION", 0); }
	else { MessageBoxW(NULL, L"myMessageBoxW installed successfully!", L"CAPTION", 0); }

	// If the threadId in the ACL is set to 0,
	// then internally EasyHook uses GetCurrentThreadId()
	ULONG ACLEntries1[1] = { 0 };
	ULONG ACLEntries2[1] = { 0 };

	// Disable the hook for the provided threadIds, enable for all others
	LhSetExclusiveACL(ACLEntries1, 1, &hHookMessageBoxA);
	LhSetExclusiveACL(ACLEntries2, 1, &hHookMessageBoxW);

	return;
}