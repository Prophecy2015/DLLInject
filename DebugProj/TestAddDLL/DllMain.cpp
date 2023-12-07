// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

int AddHook(int a, int b)
{
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(AddHook)(a, b);

		DLL_TRACE(_T("Call Add(%d, %d) = %d"), a, b, iRet);

		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(AddHook)(a, b);
}

extern "C" void DoDebugWork()
{
	BEGIN_TRANSACTION;
	DETOUR_ATTACH_EXPORT(_T("TestApp.exe"), _T("Add"), AddHook);
	END_TRANSACTION;
}

extern "C" void EndDebugWork() {}

