

#include <Windows.h>
#include <stdio.h>

#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )

//进程注入
BOOL DoInjection(char* DllPath, HANDLE hProcess)
{
    DWORD BufSize = strlen(DllPath) + 1;
    LPVOID AllocAddr = VirtualAllocEx(hProcess, NULL, BufSize, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, AllocAddr, DllPath, BufSize, NULL);
    PTHREAD_START_ROUTINE pfnStartAddr = (PTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(TEXT("Kernel32")), "LoadLibraryA");

    HANDLE hRemoteThread;
    hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, pfnStartAddr, AllocAddr, 0, NULL);
    if (hRemoteThread)
    {
        //MessageBox(NULL, TEXT("注入成功"), TEXT("提示"), MB_OK);
        return true;
    }
    else
    {
        MessageBox(NULL, TEXT("注入失败"), TEXT("提示"), MB_OK);
        return false;
    }
}


int main()
{
    wchar_t dirPath[MAX_PATH];
    wchar_t iniPath[MAX_PATH];// = L"hook.ini";
    wchar_t exe[MAX_PATH];// = L"lilim_chs.exe";
    wchar_t dllPath[MAX_PATH];// = "hook_lilim.dll";

    char dll[MAX_PATH];

    GetCurrentDirectoryW(MAX_PATH, dirPath);
    wsprintfW(iniPath, L"%ls\\%ls", dirPath, L"hook.ini");

    if (GetPrivateProfileStringW(L"FileName", L"DLL", L"", dllPath, MAX_PATH, iniPath) == 0)
    {
        printf("error, %d", GetLastError());
        MessageBoxW(NULL, L"读取ini失败！", L"错误", MB_OK);
        return 0;
    }
    WideCharToMultiByte(CP_ACP, 0, dllPath, -1, dll, MAX_PATH, NULL, NULL);
    GetPrivateProfileStringW(L"FileName", L"EXE", L"", exe, MAX_PATH, iniPath);
    //printf("dll %s\nexe %s", dll, (char*)exe);


    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (CreateProcess(NULL,   // No module name (use command line)
        exe,        // Command line
        NULL,           // Process handle not inheritable
        NULL,           // Thread handle not inheritable
        FALSE,          // Set handle inheritance to FALSE
        0,              // No creation flags
        NULL,           // Use parent's environment block
        NULL,           // Use parent's starting directory 
        &si,            // Pointer to STARTUPINFO structure
        &pi)           // Pointer to PROCESS_INFORMATION structure
        )
    {
        //开始注入
        DoInjection(dll, pi.hProcess);

        // Wait until child process exits.
        WaitForSingleObject(pi.hProcess, INFINITE);

        //// Close process and thread handles. 
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else
    {
        printf("CreateProcess failed (%d).\n", GetLastError());
        return 0;
    }

    return 0;

}