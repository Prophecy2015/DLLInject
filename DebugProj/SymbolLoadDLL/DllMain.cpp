// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

extern "C" void DoDebugWork()
{
	// ���Բ��ҷ���
	PVOID pFuncAddr = CMisc::GetFunctionsVaFromSymbols(_T("msvcrt.dll"), _T("malloc"));
	if (pFuncAddr)
	{
		PVOID pRet = ((mallocAddr)pFuncAddr)(256);
	}
}

extern "C" void EndDebugWork() {}

