#include <stdio.h>
#include <wtypes.h>
#include <TlHelp32.h>

void EnableDebugPriv();
DWORD findPidByName(char* pname);
DWORD injectDLL(const char* strDLLPath, DWORD dwProcessId);

DWORD main(int argc, char* argv[])
{
	EnableDebugPriv();

	// 得到进程名
	char *strProcName;
	strProcName = argv[1];

	// 要注入的 DLL 路径
	const char *strDLLPath = "D:\\Documents\\Visual Studio Projects\\baseLib\\x64\\Debug\\baseLib.dll";

	// 获取进程的 pid
	DWORD dwPid = findPidByName(strProcName);
	if (dwPid == 0)
	{
		printf_s("Can't Find Pid.\n");
		return 1;
	}

	injectDLL(strDLLPath, dwPid);

	return 0;
}

DWORD findPidByName(char *pname)
{
	HANDLE h;
	PROCESSENTRY32 procSnapshot;
	h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	procSnapshot.dwSize = sizeof(PROCESSENTRY32);

	do
	{
		if (!strcmp(procSnapshot.szExeFile, pname))
		{
			DWORD pid = procSnapshot.th32ProcessID;
			CloseHandle(h);
			return pid;
		}
	} while (Process32Next(h, &procSnapshot));

	CloseHandle(h);
	return 0;
}

DWORD injectDLL(const char* strDLLPath, DWORD dwProcessId)
{
	// Calculate the number of bytes needed for the DLL's pathname
	DWORD dwSize = (strlen(strDLLPath) + 1) * sizeof(char);

	// Get process handle passing in the process ID
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, dwProcessId);
	if (hProcess == NULL)
	{
		printf("[-] Error: Could not open process for PID (%d).\n", dwProcessId);
		return(1);
	}

	// Allocate space in the remote process for the pathname
	LPVOID pszLibFileRemote = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		printf("[-] Error: Could not allocate memory inside PID (%d).\n", dwProcessId);
		return(1);
	}

	// Copy the DLL's pathname to the remote process address space
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (LPCVOID)strDLLPath, dwSize, NULL);
	if (n == 0)
	{
		printf("[-] Error: Could not write any bytes into the PID [%d] address space.\n", dwProcessId);
		return(1);
	}

	

	// Get the real address of LoadLibraryW in Kernel32.dll
	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("Kernel32"), "LoadLibraryA");
	if (pfnThreadRtn == NULL)
	{
		printf("[-] Error: Could not find LoadLibraryA function inside kernel32.dll library.\n");
		return(1);
	}

	// Create a remote thread that calls LoadLibraryA(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
	{
		printf("[-] Error: Could not create the Remote Thread.\n");
		DWORD err = GetLastError();
		return(1);
	}
	else
		printf("[+] Success: DLL injected via CreateRemoteThread().\n");

	// Wait for the remote thread to terminate
	WaitForSingleObject(hThread, INFINITE);

	// Free the remote memory that contained the DLL's pathname and close Handles
	if (pszLibFileRemote != NULL)
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);

	if (hThread != NULL)
		CloseHandle(hThread);

	if (hProcess != NULL)
		CloseHandle(hProcess);

	return(0);
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}
