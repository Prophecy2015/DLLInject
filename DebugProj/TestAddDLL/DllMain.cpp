// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Misc.h"

typedef PVOID(*mallocAddr)(int);

int AddHook(int a, int b)
{
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(AddHook)(a, b);
		
		BYTE data[64] = { 11,22,33,44,55,66,77,88,99 };
		DLL_TRACE(_T("Call Add(%d, %d) = %d (%s)"), a, b, iRet, CMisc::FormatHex(data, 9));

		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(AddHook)(a, b);
}

extern "C" void DoDebugWork()
{
	BEGIN_TRANSACTION;
	DETOUR_ATTACH_EXPORT(_T("TestApp_d.exe"), _T("Add"), AddHook);
	END_TRANSACTION;
}

extern "C" void EndDebugWork() {}

