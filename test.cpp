/* TEST INCLUDE API HOOK TO NOTEPAD++ */
//									  //
//									  //
//									  //
/*                                    */

#include "EasyHookLib/easyhook.h"

#if _WIN64
#pragma comment(lib, "EasyHookLib/EasyHook64.lib")
#else
#pragma comment(lib, "EasyHookLib/EasyHook32.lib")
#endif

#include <iostream>
#include <Windowsx.h>
#include <TlHelp32.h>

using namespace std;

int main(int argc, char*  argv[]) {
	PROCESSENTRY32 ProcEntry32;
	ProcEntry32.dwSize = sizeof(PROCESSENTRY32);

	HANDLE hdlSnapShot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(hdlSnapShot, &ProcEntry32) == TRUE)
	{
		while (Process32Next(hdlSnapShot, &ProcEntry32) == TRUE)
		{
			if (wcscmp(ProcEntry32.szExeFile, L"notepad++.exe") == 0)
			{

				wcout << L"Notepad++ Process ID: " << ProcEntry32.th32ProcessID << endl;


				WCHAR dllToInject[16] = L"InjectedDLL.dll";
				wprintf(L"Attempting to inject: %s\n\n", dllToInject);

				// Inject dllToInject into the target process Id, passing 
				// freqOffset as the pass through data.
				NTSTATUS nt = RhInjectLibrary(
					ProcEntry32.th32ProcessID,  // The process to inject into
					0,							// ThreadId to wake up upon injection
					EASYHOOK_INJECT_DEFAULT,	
					NULL,						// 32-bit
					dllToInject,				// 64-bit
					NULL,						// data to send to injected DLL entry point
					0							// size of data to send
				);

				if (nt != 0)
				{
					printf("RhInjectLibrary failed with error code = %d\n", nt);
					PWCHAR err = RtlGetLastErrorString();
					std::wcout << err << "\n";
				}
				else
				{
					std::wcout << L"Library injected successfully.\n";
				}

				system("pause");
				return 0;	
			}
		}
	}

	CloseHandle(hdlSnapShot);

	return 0;
}