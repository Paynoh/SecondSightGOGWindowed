#include <Windows.h>
#include <d3d9.h>
#include "MinHook.h"
#include "FindPattern.hpp"
LPDIRECT3DDEVICE9 pDevice = nullptr;

using CreateDevice_t = HRESULT(WINAPI*)(IDirect3D9*, UINT, D3DDEVTYPE, HWND, DWORD, D3DPRESENT_PARAMETERS*, IDirect3DDevice9**);
using Reset_t = HRESULT(WINAPI*)(IDirect3DDevice9*, D3DPRESENT_PARAMETERS*);


CreateDevice_t oCreateDevice = nullptr;
Reset_t oReset = nullptr;


HRESULT WINAPI HookedCreateDevice(
    IDirect3D9* pD3D9,
    UINT Adapter,
    D3DDEVTYPE DeviceType,
    HWND hFocusWindow,
    DWORD BehaviorFlags,
    D3DPRESENT_PARAMETERS* pPresentationParameters,
    IDirect3DDevice9** ppReturnedDeviceInterface)
{
    
    pPresentationParameters->Windowed = TRUE;
    //pPresentationParameters->FullScreen_RefreshRateInHz = 0;
    return oCreateDevice(pD3D9, Adapter, DeviceType, hFocusWindow, BehaviorFlags, pPresentationParameters, ppReturnedDeviceInterface);
}

HRESULT WINAPI HookedReset(IDirect3DDevice9* pDevice, D3DPRESENT_PARAMETERS* pPresentationParameters)
{
    pPresentationParameters->Windowed = TRUE;
    pPresentationParameters->FullScreen_RefreshRateInHz = 0;
    return oReset(pDevice, pPresentationParameters);
}

HWND WINAPI HookedCreateWindowEx(DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle, int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu, HINSTANCE hInstance, LPVOID lpParam)
{
    dwStyle = (dwStyle & ~WS_POPUP) | WS_OVERLAPPEDWINDOW;
    return oCreateWindowEx(dwExStyle, lpClassName, lpWindowName, dwStyle, 600, 400, 800, 600, hWndParent, hMenu, hInstance, lpParam);
}


__declspec(dllexport) BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
       
        //oCreateWindowEx = PatternScanner::FindPattern("secondsight.exe","\xff\x15\x00\x00\x00\x00\x8b\xf0\x85\xf6\x5f", "xx????xxxxx").as<CreateWindowEx_t>();
		oReset = PatternScanner::FindPattern("d3d9.dll","\x8b\xff\x55\x8b\xec\x83\xe4\x00\x81\xec\x00\x00\x00\x00\xa1\x00\x00\x00\x00\x33\xc4\x89\x84\x24\x00\x00\x00\x00\x53\x8b\x5d\x00\x8b\xcb", "xxxxxxx?xx????x????xxxxx????xxx?xx").as<Reset_t>();
		oCreateDevice = PatternScanner::FindPattern("d3d9.dll","\x8b\xff\x55\x8b\xec\x51\x51\x56\x8b\x75\x00\x8b\xce\xf7\xd9\x57\x1b\xc9\x8d\x46\x00\x23\xc8\x6a\x00\x51\x8d\x4d\x00\xe8\x00\x00\x00\x00\xf7\x46\x00\x00\x00\x00\x00\x75\x00\x83\xbe\x00\x00\x00\x00\x00\x74\x00\x8b\x7e","xxxxxxxxxx?xxxxxxxxx?xxx?xxx?x????xx?????x?xx?????x?xx").as<CreateDevice_t>();
       

        
        
        MH_Initialize();
       //MH_CreateHook(reinterpret_cast<LPVOID>(oCreateWindowEx), &HookedCreateWindowEx, reinterpret_cast<void**>(&oCreateWindowEx));
        MH_CreateHook(reinterpret_cast<LPVOID>(oReset), HookedReset, reinterpret_cast<void**>(&oReset));
        MH_CreateHook(reinterpret_cast<LPVOID>(oCreateDevice), HookedCreateDevice, reinterpret_cast<void**>(&oCreateDevice));
        MH_EnableHook(MH_ALL_HOOKS);
        
		/*
        char buffer[512];
        sprintf_s(buffer, "oReset: %p, CreateDevice: %p, CreateWindow: %p",oReset,oCreateDevice , oCreateWindowEx);
        MessageBoxA(NULL, buffer, "Debug", MB_OK);
        */

    }

    return TRUE;
}