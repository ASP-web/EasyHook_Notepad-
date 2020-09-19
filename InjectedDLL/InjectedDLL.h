#pragma once

#include "../EasyHookLib/easyhook.h"

#if _WIN64
#pragma comment(lib, "../EasyHookLib/EasyHook64.lib")
#else
#pragma comment(lib, "../EasyHookLib/EasyHook32.lib")
#endif

/* Define DLL IMPORT FUNCTIONS AND METHODS */
#ifdef INJECTEDDLL
INJECTEDDLL void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* inRemoteInfo);
#else
/* Define to EXE files DLL import table */
#define INJECTEDDLL extern "C" declspec(dllimport)
#endif


