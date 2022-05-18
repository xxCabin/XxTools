// dllmain.cpp : 定义 DLL 应用程序的入口点。
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
CHAR szDllPath[MAX_PATH] = { 0 };  //保存要注入的DLL的路径
DWORD dwPID = 0;                 //保存要注入的进程的PID

// 提升当前进程令牌权限
if (!EnbalePrivileges(GetCurrentProcess(), SE_DEBUG_NAME))
{
printf("权限提升失败\n");
}

dwPID = GetPID(PROCESS_NAME);
if (dwPID == 0)
{
printf("没有找到要注入的进程\n");
goto exit;
}

GetCurrentDirectory(MAX_PATH, szDllPath);  //获取程序的目录
strcat(szDllPath, "\\");
strcat(szDllPath, DLL_NAME);               //与DLL名字拼接得到DLL的完整路径
printf("要注入的进程名:%s PID:%d\n", PROCESS_NAME, dwPID);
printf("要注入的DLL的完整路径%s\n", szDllPath);

if (InjectDll(dwPID, szDllPath))
{
printf("Dll注入成功\n");
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
	CHAR szDesktopFile[MAX_PATH] = { 0 };  //保存系统桌面路径
	CHAR szFullFilePath[MAX_PATH] = { 0 }; //保存完成的加载DLL文件的文件路径
	DWORD dwRetLen = 0, dwFileLen = 0;
	BOOL bRet = TRUE;

	//获取桌面路径
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
			if (hFile == INVALID_HANDLE_VALUE)   //打开文件错误
			{
				if (GetLastError() == 32)    //错误码是不是其他进程正在使用这个文件,是的话等待一会在继续打开
				{
					Sleep(200);
					continue;
				}
				else break;
			}
			else
			{
				GetModuleFileName(NULL, szFullFilePath, MAX_PATH);    //获取加载DLL的进程的完整路径
				dwFileLen = strlen(szFullFilePath);
				szFullFilePath[dwFileLen] = '\r'; //由于是在WIN7运行，换行符是\r\n
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