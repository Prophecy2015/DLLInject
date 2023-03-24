// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

extern "C" void DoDebugWork()
{
	// 测试查找符号
	PVOID pFuncAddr = CMisc::GetFunctionsVaFromSymbols(_T("msvcrt.dll"), _T("malloc"));
	if (pFuncAddr)
	{
		PVOID pRet = ((mallocAddr)pFuncAddr)(256);
	}
}

extern "C" void EndDebugWork() {}

