#pragma once

DWORD GetPID(PCHAR pProName); //���ݽ�������ȡPID
VOID ShowError(PCHAR msg);    //��ӡ������Ϣ
BOOL EnbalePrivileges(HANDLE hProcess, char *pszPrivilegesName);    //��������Ȩ��
