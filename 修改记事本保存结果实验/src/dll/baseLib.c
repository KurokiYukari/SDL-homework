#include <Windows.h>
#include <stdio.h>

LONG IATHook(
    __in_opt void* pImageBase,
    __in_opt char* pszImportDllName,
    __in char* pszRoutineName,
    __in void* pFakeRoutine,
    __out HANDLE* phHook
);

LONG UnIATHook(__in HANDLE hHook);

void* GetIATHookOrign(__in HANDLE hHook);

typedef int(__stdcall* LPFN_WriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
    );

HANDLE g_hHook_WriteFile = NULL;

BOOL __stdcall Fake_WriteFile(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
)
{
    LPFN_WriteFile fnOrigin = (LPFN_WriteFile)GetIATHookOrign(g_hHook_WriteFile);
    
    if (!strcmp(lpBuffer, "666"))
    {
        return fnOrigin(hFile, "999", nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    return fnOrigin(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

void WINAPI hookWriteFile()
{
    do
    {
        IATHook(
            GetModuleHandleW(NULL),
            "Kernel32.dll",
            "WriteFile",
            Fake_WriteFile,
            &g_hHook_WriteFile
        );
    } while (FALSE);
}

BOOL WINAPI DllMain(
    HINSTANCE hinstDLL,  // handle to DLL module
    DWORD fdwReason,     // reason for calling function
    LPVOID lpReserved)  // reserved
{
    // Perform actions based on the reason for calling.
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        // Initialize once for each new process.
        // Return FALSE to fail DLL load.
        hookWriteFile();
        break;

    case DLL_THREAD_ATTACH:
        // Do thread-specific initialization.
        break;

    case DLL_THREAD_DETACH:
        // Do thread-specific cleanup.
        break;

    case DLL_PROCESS_DETACH:
        // Perform any necessary cleanup.
        break;
    }
    return TRUE;  // Successful DLL_PROCESS_ATTACH.
}
