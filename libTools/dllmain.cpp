// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"

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

/*
int main()
{
CHAR szDllPath[MAX_PATH] = { 0 };  //����Ҫע���DLL��·��
DWORD dwPID = 0;                 //����Ҫע��Ľ��̵�PID

// ������ǰ��������Ȩ��
if (!EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
{
printf("Ȩ������ʧ��\n");
}

dwPID = GetPID(PROCESS_NAME);
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

if (InjectDll(dwPID, szDllPath))
{
printf("Dllע��ɹ�\n");
}
exit:
system("pause");

return 0;
}
*/
/*
DWORD WINAPI ThreadProc(LPVOID lpParameter)
{
	HANDLE hFile = NULL;
	CHAR szDesktopFile[MAX_PATH] = { 0 };  //����ϵͳ����·��
	CHAR szFullFilePath[MAX_PATH] = { 0 }; //������ɵļ���DLL�ļ����ļ�·��
	DWORD dwRetLen = 0, dwFileLen = 0;
	BOOL bRet = TRUE;

	//��ȡ����·��
	bRet = SHGetSpecialFolderPath(NULL, szDesktopFile, CSIDL_DESKTOP, TRUE);
	if (bRet)
	{
		strcat(szDesktopFile, "\\");
		strcat(szDesktopFile, FILE_NAME);
		while (TRUE)
		{
			hFile = CreateFile(szDesktopFile,
				GENERIC_READ | GENERIC_WRITE,
				0, NULL,
				OPEN_ALWAYS,
				FILE_ATTRIBUTE_NORMAL, NULL);
			if (hFile == INVALID_HANDLE_VALUE)   //���ļ�����
			{
				if (GetLastError() == 32)    //�������ǲ���������������ʹ������ļ�,�ǵĻ��ȴ�һ���ڼ�����
				{
					Sleep(200);
					continue;
				}
				else break;
			}
			else
			{
				GetModuleFileName(NULL, szFullFilePath, MAX_PATH);    //��ȡ����DLL�Ľ��̵�����·��
				dwFileLen = strlen(szFullFilePath);
				szFullFilePath[dwFileLen] = '\r'; //��������WIN7���У����з���\r\n
				szFullFilePath[dwFileLen + 1] = '\n';
				SetFilePointer(hFile, 0, NULL, FILE_END);
				WriteFile(hFile, szFullFilePath, dwFileLen + 2, &dwRetLen, NULL);
				if (hFile) CloseHandle(hFile);
				break;
			}
		}
	}

	return 0;
}*/