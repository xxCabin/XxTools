#include "stdafx.h"
#include "Inject.h"

#include "Common.h"

#include <TlHelp32.h>

typedef DWORD(WINAPI *pFnZwCreateThreadEx)(PHANDLE, ACCESS_MASK, LPVOID,
	HANDLE, LPTHREAD_START_ROUTINE,
	LPVOID, BOOL, DWORD, DWORD, DWORD, LPVOID);

#define FILE_NAME "result.txt"
#define PROCESS_NAME "taskmgr.exe"    //Ҫע��Ľ����������������������Ľ�����
#define DLL_NAME "InjectDll.dll"  //Ҫע���DLL������

Inject::Inject()
{
}

Inject::~Inject()
{
}

int Inject::InjectDll(std::string strProcessName, std::string strDllPath)
{
	CHAR szDllPath[MAX_PATH] = { 0 };  //����Ҫע���DLL��·��
	DWORD dwPID = 0;                   //����Ҫע��Ľ��̵�PID

	// ������ǰ��������Ȩ��
	if (!EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
	{
		printf("Ȩ������ʧ��\n");
	}

	dwPID = GetPID((PCHAR)strProcessName.c_str());
	if (dwPID == 0)
	{
		printf("û���ҵ�Ҫע��Ľ���\n");
		goto exit;
	}

	GetCurrentDirectory(MAX_PATH, szDllPath);  //��ȡ�����Ŀ¼
	strcat(szDllPath, "\\");
	strcat(szDllPath, DLL_NAME);               //��DLL����ƴ�ӵõ�DLL������·��
	printf("Ҫע��Ľ�����:%s PID:%d\n", PROCESS_NAME, dwPID);
	printf("Ҫע���DLL������·��%s\n", szDllPath);

	if (InjectDll_CreateRemoteThread(dwPID, szDllPath))
	{
		printf("Dllע��ɹ�\n");
	}
exit:
	system("pause");

	return 0;
}

BOOL Inject::InjectDll_CreateRemoteThread(DWORD dwPid, CHAR szDllName[])
{
	BOOL bRet = TRUE;
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	HMODULE hKernel32 = NULL;
	DWORD dwSize = 0;
	LPVOID pDllPathAddr = NULL;
	PVOID pLoadLibraryAddr = NULL;

	// ��ע����̣���ȡ���̾��
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		bRet = FALSE;
		goto exit;
	}

	// ��ע������������������DLL���·�������ڴ�ռ�
	dwSize = 1 + strlen(szDllName);
	pDllPathAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pDllPathAddr)
	{
		ShowError("VirtualAllocEx");
		bRet = FALSE;
		goto exit;
	}

	// ��DLL����·����д�������
	if (!WriteProcessMemory(hProcess, pDllPathAddr, szDllName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		bRet = FALSE;
		goto exit;
	}


	hKernel32 = LoadLibrary("kernel32.dll");
	if (hKernel32 == NULL)
	{
		ShowError("LoadLibrary");
		bRet = FALSE;
		goto exit;
	}

	// ��ȡLoadLibraryA������ַ
	pLoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
	if (pLoadLibraryAddr == NULL)
	{
		ShowError("GetProcAddress ");
		bRet = FALSE;
		goto exit;
	}

	//����Զ���߳̽���DLLע��
	hRemoteThread = CreateRemoteThread(hProcess, NULL, 0,
		(LPTHREAD_START_ROUTINE)pLoadLibraryAddr,
		pDllPathAddr, 0, NULL);
	if (hRemoteThread == NULL)
	{
		ShowError("CreateRemoteThread");
		bRet = FALSE;
		goto exit;
	}

exit:
	if (hKernel32) FreeLibrary(hKernel32);
	if (hProcess) CloseHandle(hProcess);
	if (hRemoteThread) CloseHandle(hRemoteThread);

	return bRet;
}

BOOL Inject::InjectDll_ZwCreateThreadEx(DWORD dwPid, CHAR szDllName[])
{
	BOOL bRet = TRUE;
	HANDLE hProcess = NULL, hRemoteThread = NULL;
	HMODULE hKernel32 = NULL, hNtDll = NULL;
	DWORD dwSize = 0;
	LPVOID pDllPathAddr = NULL;
	PVOID pLoadLibraryAddr = NULL;
	pFnZwCreateThreadEx ZwCreateThreadEx = NULL;

	// ��ע����̣���ȡ���̾��
	hProcess = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		bRet = FALSE;
		goto exit;
	}

	// ��ע������������������DLL���·�������ڴ�ռ�
	dwSize = 1 + strlen(szDllName);
	pDllPathAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pDllPathAddr)
	{
		ShowError("VirtualAllocEx");
		bRet = FALSE;
		goto exit;
	}

	// ��DLL���·����д�������
	if (!WriteProcessMemory(hProcess, pDllPathAddr, szDllName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		bRet = FALSE;
		goto exit;
	}


	hKernel32 = LoadLibrary("kernel32.dll");
	if (hKernel32 == NULL)
	{
		ShowError("LoadLibrary kernel32");
		bRet = FALSE;
		goto exit;
	}

	// ��ȡLoadLibraryA������ַ
	pLoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
	if (pLoadLibraryAddr == NULL)
	{
		ShowError("GetProcAddress LoadLibraryA");
		bRet = FALSE;
		goto exit;
	}

	hNtDll = LoadLibrary("ntdll.dll");
	if (hNtDll == NULL)
	{
		ShowError("LoadLibrary ntdll");
		bRet = FALSE;
		goto exit;
	}

	ZwCreateThreadEx = (pFnZwCreateThreadEx)GetProcAddress(hNtDll, "ZwCreateThreadEx");
	if (!ZwCreateThreadEx)
	{
		ShowError("GetProcAddress ZwCreateThreadEx");
		bRet = FALSE;
		goto exit;
	}

	ZwCreateThreadEx(&hRemoteThread, PROCESS_ALL_ACCESS, NULL,
		hProcess, (LPTHREAD_START_ROUTINE)pLoadLibraryAddr,
		pDllPathAddr, 0, 0, 0, 0, NULL);
	if (hRemoteThread == NULL)
	{
		ShowError("ZwCreateThreadEx");
		bRet = FALSE;
		goto exit;
	}
exit:
	if (hKernel32) FreeLibrary(hKernel32);
	if (hNtDll) FreeLibrary(hNtDll);
	if (hProcess) CloseHandle(hProcess);
	if (hRemoteThread) CloseHandle(hRemoteThread);
	return bRet;
}

BOOL Inject::InjectDll_APC(DWORD dwPid, CHAR szDllName[])
{
	BOOL bRet = TRUE;
	HANDLE hProcess = NULL, hThread = NULL, hSnap = NULL;
	HMODULE hKernel32 = NULL;
	DWORD dwSize = 0;
	PVOID pDllPathAddr = NULL;
	PVOID pLoadLibraryAddr = NULL;
	THREADENTRY32 te32 = { 0 };

	// ��ע����̣���ȡ���̾��
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (NULL == hProcess)
	{
		ShowError("OpenProcess");
		bRet = FALSE;
		goto exit;
	}

	// ��ע������������������DLL���·�������ڴ�ռ�
	dwSize = 1 + strlen(szDllName);
	pDllPathAddr = VirtualAllocEx(hProcess, NULL, dwSize, MEM_COMMIT, PAGE_READWRITE);
	if (!pDllPathAddr)
	{
		ShowError("VirtualAllocEx");
		bRet = FALSE;
		goto exit;
	}

	// ��DLL���·����д�������
	if (!WriteProcessMemory(hProcess, pDllPathAddr, szDllName, dwSize, NULL))
	{
		ShowError("WriteProcessMemory");
		bRet = FALSE;
		goto exit;
	}


	hKernel32 = LoadLibrary("kernel32.dll");
	if (hKernel32 == NULL)
	{
		ShowError("LoadLibrary");
		bRet = FALSE;
		goto exit;
	}

	// ��ȡLoadLibraryA������ַ
	pLoadLibraryAddr = GetProcAddress(hKernel32, "LoadLibraryA");
	if (pLoadLibraryAddr == NULL)
	{
		ShowError("GetProcAddress");
		bRet = FALSE;
		goto exit;
	}

	//����߳̿���
	hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (!hSnap)
	{
		ShowError("CreateToolhelp32Snapshot");
		bRet = FALSE;
		goto exit;
	}

	//�����߳�
	te32.dwSize = sizeof(te32);
	if (Thread32First(hSnap, &te32))
	{
		do
		{
			//����̵߳Ľ���ID�ǲ���Ҫע��Ľ��̵�PID
			if (te32.th32OwnerProcessID == dwPid)
			{
				hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
				if (hThread)
				{
					QueueUserAPC((PAPCFUNC)pLoadLibraryAddr, hThread, (ULONG_PTR)pDllPathAddr);
					CloseHandle(hThread);
					hThread = NULL;
				}
				else
				{
					ShowError("OpenThread");
					bRet = FALSE;
					goto exit;
				}
			}
		} while (Thread32Next(hSnap, &te32));
	}
exit:
	if (hKernel32) FreeLibrary(hKernel32);
	if (hProcess) CloseHandle(hProcess);
	if (hThread) CloseHandle(hThread);
	return bRet;
}

BOOL Inject::InjectDll_AppInitDLL(DWORD dwPid, CHAR szDllName[])
{
	BOOL bRet = TRUE;
	HKEY hKey = NULL;
	CHAR szAppKeyName[] = { "AppInit_DLLs" };
	CHAR szLoadAppKeyName[] = { "LoadAppInit_DLLs" };
	DWORD dwLoadAppInit = 1; //����LoadAppInit_DLLs��ֵ

							 //����Ӧע����
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows",
		0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS)
	{
		ShowError("RegOpenKeyEx");
		bRet = FALSE;
		goto exit;
	}

	//����AppInit_DLLsΪ��Ӧ��DLL·��
	if (RegSetValueEx(hKey, szAppKeyName, 0, REG_SZ, (PBYTE)szDllName, strlen(szDllName) + 1) != ERROR_SUCCESS)
	{
		ShowError("RegSetValueEx");
		bRet = FALSE;
		goto exit;
	}

	//��LoadAppInit_DLLs��ֵ��Ϊ1
	if (RegSetValueEx(hKey, szLoadAppKeyName, 0, REG_DWORD, (PBYTE)&dwLoadAppInit, sizeof(dwLoadAppInit)) != ERROR_SUCCESS)
	{
		ShowError("RegSetValueEx");
		bRet = FALSE;
		goto exit;
	}
exit:
	return bRet;
}
