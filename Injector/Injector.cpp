// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <string>
#include <ctype.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <atlstr.h>
#include <Shlwapi.h>
#include "resource.h"

//Library needed by Linker to check file existance
#pragma comment(lib, "Shlwapi.lib")

using namespace std;

bool Inject(const int& pid, const string& DLL_Path, const int& mode);
void help();

string ExePath() {
	char buffer[MAX_PATH];
	GetModuleFileName(NULL, buffer, MAX_PATH);
	string::size_type pos = string(buffer).find_last_of("\\/");
	return string(buffer).substr(0, pos);
}

int main(int argc, char** argv)
{
	if (argc < 3) 
	{
		help();
		return EXIT_FAILURE;
	}
	if  ((argc > 3) && (PathFileExists(argv[3]) == FALSE))
	{
		cerr << "[!]DLL file does NOT exist! - exiting..." << endl;
		return EXIT_FAILURE;
	}

	if (isdigit(argv[1][0]))
	{
		cout << "[+]Terget Process ID: " << atoi(argv[1]) << endl;
		if ((atoi(argv[2])) == 0){
			Inject(atoi(argv[1]), argv[3], atoi(argv[2]));
		}
		else {
			Inject(atoi(argv[1]), "dummy", atoi(argv[2]));
		}
		
	}

	return EXIT_SUCCESS;
}

bool Inject(const int& pid, const string& DLL_Path,const int& status)
{
	string path_final = DLL_Path;
	PVOID DLLAlloc, shellcodealloc;
	int IsDLLWriteOK, IsShellcodeWriteOK;
	HANDLE ThreadDLL, ThreadShellCode;
	
	ThreadShellCode = NULL;
	shellcodealloc = NULL;
	ThreadDLL = NULL;
	DLLAlloc =  NULL;
	IsDLLWriteOK = NULL;


	if (PathIsRelative(DLL_Path.c_str()))
	{
		const string cwd_path = ExePath();
		path_final = cwd_path + '\\' + DLL_Path;
	}

	long dll_size = path_final.length();

	// getting target process handle
	HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		
	if (hProc == NULL)
	{
		cerr << "[!]Fail to open target process!" << endl;
		return false;
	}
	cout << "[+]Opening Target Process..." << endl;

	// DLL injection 
	if (status == 0) {
		DLLAlloc = VirtualAllocEx(hProc, NULL, dll_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		IsDLLWriteOK = WriteProcessMemory(hProc, DLLAlloc, path_final.c_str(), dll_size, 0);
		LPTHREAD_START_ROUTINE addrLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(LoadLibrary("kernel32"), "LoadLibraryA");
		DWORD dWord;
		ThreadDLL = CreateRemoteThread(hProc, NULL, 0, addrLoadLibrary, DLLAlloc, 0, &dWord);
		CloseHandle(hProc);
	}


	if (status == 1) {
		// loading shellcode from rsc
		HRSRC shellcodeResource = FindResource(NULL, MAKEINTRESOURCE(IDR_CALC2_BIN1), "CALC2_BIN");
		DWORD shellcodeSize = SizeofResource(NULL, shellcodeResource);
		HGLOBAL shellcodeResouceData = LoadResource(NULL, shellcodeResource);

		shellcodealloc = VirtualAllocEx(hProc, NULL, shellcodeSize, (MEM_RESERVE | MEM_COMMIT), PAGE_EXECUTE_READWRITE);
		IsShellcodeWriteOK = WriteProcessMemory(hProc, shellcodealloc, shellcodeResouceData, shellcodeSize, NULL);
		ThreadShellCode = CreateRemoteThread(hProc, NULL, 0, (LPTHREAD_START_ROUTINE)shellcodealloc, NULL, 0, NULL);
		CloseHandle(hProc);
	 }
	// checks
	if ((DLLAlloc  == NULL) && (shellcodealloc == NULL))
	{
		cerr << "[!]Fail to allocate memory in Target Process." << endl;
		return false;
	}
	cout << "[+]Allocating memory in Targer Process." << endl;

	if ((IsDLLWriteOK== NULL) && (IsShellcodeWriteOK == NULL))
	{
		cerr << "[!]Failed to write in Target Process memory." << endl;
		return false;
	}
	cout << "[+]Creating Remote Thread in Target Process" << endl;

	if ((ThreadDLL == NULL) && (ThreadShellCode == NULL))
	{
		cerr << "[!]Failed to create Remote Thread" << endl;
		return false;
	}
	
	if ((hProc != NULL) && (DLLAlloc != NULL) && (IsDLLWriteOK != ERROR_INVALID_HANDLE) && (ThreadDLL != NULL))
	{
		cout << "[+]DLL & Shellcode Successfully Injected :)" << endl;
		return true;
	}
	return true;
}

void help()
{
	cout << "\nUsage: DS_Injector.exe <target process ID> <0-1> [DLL Path to inject]" << endl;
	cout << "Example: DS_Injector.exe 4242 2 InjectDLL.dll\n " << endl;
	cout << "[0] - Create Remote Thread - DLL Injection" << endl;
	cout << "[1] - Create Remote Thread - Shellcode Injection *\n" << endl;
	cout << "[*] Shellcode can be replaced in the 'resource' section of the project.>" << endl;
	cout << "[*] WARNING - it might kill the parent process" << endl;
	
}