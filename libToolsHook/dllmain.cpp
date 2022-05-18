// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "stdafx.h"

void Hook();
void UnHook();


void Hook()
{
	//��ʼ����
	DetourTransactionBegin();
	//�����߳���Ϣ
	DetourUpdateThread(GetCurrentThread());
	//hook
	//DetourAttach(&(PVOID&)old, new);

	//��������
	DetourTransactionCommit();
}

void UnHook()
{
	//��ʼ����
	DetourTransactionBegin();
	//�����߳���Ϣ
	DetourUpdateThread(GetCurrentThread());
	//unhook
	//DetourDetach(&(PVOID&)old, new);

	//��������
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

