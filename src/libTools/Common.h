#pragma once

DWORD GetPID(PCHAR pProName); //根据进程名获取PID
VOID ShowError(PCHAR msg);    //打印错误信息
BOOL EnbalePrivileges(HANDLE hProcess, char *pszPrivilegesName);    //提升进程权限
