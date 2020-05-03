// dllmain.cpp : Defines the entry point for the DLL application.//
#include "pch.h"
#include "windows.h"
#include <stdio.h>
#include <atlstr.h>
#include <iostream>


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    CString text;
    text.Format(L"Current PID: %d", ::GetCurrentProcessId());

    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:

        ::MessageBox(nullptr, text, L"Injected DLL", MB_OK);

    case DLL_THREAD_ATTACH:
        //::MessageBox(nullptr, text, L"Single Instance", MB_OK);
    case DLL_THREAD_DETACH:
        //::MessageBox(nullptr, text, L"Single Instance", MB_OK);
    case DLL_PROCESS_DETACH:
        //::MessageBox(nullptr, text, L"Single Instance", MB_OK);
        break;
    }
    return TRUE;
}


