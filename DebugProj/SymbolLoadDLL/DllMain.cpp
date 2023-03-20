// dllmain.cpp : ���� DLL Ӧ�ó������ڵ㡣
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

PVOID __cdecl MallocHook(size_t size)
{
	if (TRUE == CMisc::BeginWork())
	{
		PVOID pRet = CALL_OLD(MallocHook)(size);
		DLL_TRACE("MallocHook(%d) = %p", size, pRet);

		CMisc::EndWork();
		return pRet;
	}

	return CALL_OLD(MallocHook)(size);
}

extern "C" void DoDebugWork()
{
	// ���Բ��ҷ���
	PVOID pFuncAddr = CMisc::GetFunctionsVaFromSymbols("msvcrt.dll", "malloc");
	//if (pFuncAddr)
	//{
	//	PVOID pRet = ((mallocAddr)pFuncAddr)(256);
	//}

	// ��̬��׮
	BEGIN_TRANSACTION
	DETOUR_ATTACH_SYMBOL("msvcrt.dll", "malloc", MallocHook);// 
	END_TRANSACTION
}

extern "C" void EndDebugWork() {}

