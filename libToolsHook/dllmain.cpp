// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "stdafx.h"

void Hook();
void UnHook();


void Hook()
{
	//开始事务
	DetourTransactionBegin();
	//更新线程信息
	DetourUpdateThread(GetCurrentThread());
	//hook
	//DetourAttach(&(PVOID&)old, new);

	//结束事务
	DetourTransactionCommit();
}

void UnHook()
{
	//开始事务
	DetourTransactionBegin();
	//更新线程信息
	DetourUpdateThread(GetCurrentThread());
	//unhook
	//DetourDetach(&(PVOID&)old, new);

	//结束事务
	DetourTransactionCommit();
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
					 )
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
		Hook();
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}

