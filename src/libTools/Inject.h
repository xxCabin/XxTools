#pragma once

#include <string>

class Inject
{
public:
	Inject();
	~Inject();

	int InjectDll(std::string strProcessName, std::string strDllPath);

private:
	BOOL InjectDll_CreateRemoteThread(DWORD dwPid, CHAR szDllName[]);  //×¢ÈëDLL
	BOOL InjectDll_ZwCreateThreadEx(DWORD dwPid, CHAR szDllName[]);
	BOOL InjectDll_APC(DWORD dwPid, CHAR szDllName[]);
	BOOL InjectDll_AppInitDLL(DWORD dwPid, CHAR szDllName[]);
};



