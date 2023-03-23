// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

PVOID __cdecl MallocHook(size_t size)
{
	if (TRUE == CMisc::BeginWork())
	{
		PVOID pRet = CALL_OLD(MallocHook)(size);
		DLL_TRACE(_T("MallocHook(%d) = %p"), size, pRet);

		CMisc::EndWork();
		return pRet;
	}

	return CALL_OLD(MallocHook)(size);
}

extern "C" void DoDebugWork()
{
	// ���Բ��ҷ���
	PVOID pFuncAddr = CMisc::GetFunctionsVaFromSymbols(_T("msvcrt.dll"), _T("malloc"));
	//if (pFuncAddr)
	//{
	//	PVOID pRet = ((mallocAddr)pFuncAddr)(256);
	//}

	// ��̬��׮
	BEGIN_TRANSACTION
	DETOUR_ATTACH_SYMBOL(_T("msvcrt.dll"), _T("malloc"), MallocHook);// 
	END_TRANSACTION
}

extern "C" void EndDebugWork() {}

