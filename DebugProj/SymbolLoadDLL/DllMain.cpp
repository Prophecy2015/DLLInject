// dllmain.cpp : 定义 DLL 应用程序的入口点。
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
	// 测试查找符号
	PVOID pFuncAddr = CMisc::GetFunctionsVaFromSymbols("msvcrt.dll", "malloc");
	//if (pFuncAddr)
	//{
	//	PVOID pRet = ((mallocAddr)pFuncAddr)(256);
	//}

	// 动态插桩
	BEGIN_TRANSACTION
	DETOUR_ATTACH_SYMBOL("msvcrt.dll", "malloc", MallocHook);// 
	END_TRANSACTION
}

extern "C" void EndDebugWork() {}

