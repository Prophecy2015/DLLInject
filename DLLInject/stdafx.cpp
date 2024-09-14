
// stdafx.cpp : 只包括标准包含文件的源文件
// DLLInject.pch 将作为预编译头
// stdafx.obj 将包含预编译类型信息

#include "stdafx.h"


BOOL EnablePrivilegeDebug(BOOL bEnable) {
	BOOL bRet = FALSE;
	HANDLE hToken;
	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return FALSE;
	}
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (TRUE == LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid)) {
		bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		if (FALSE == bRet)
		{
			TRACE("AdjustTokenPrivileges FALSE = %u",  GetLastError());
		}
	}

	CloseHandle(hToken);

	return bRet;
}