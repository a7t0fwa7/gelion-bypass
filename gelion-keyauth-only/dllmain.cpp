#include "pch.h"
#include "keyauth/gelion.hpp"
BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:\
        DisableThreadLibraryCalls(hModule);
        globals->does_settings_exist();
        keyauth->scan_signatures();
        keyauth->initialize_hooks();
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

