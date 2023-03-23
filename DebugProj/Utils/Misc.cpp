#include "Misc.h"
#include "stdio.h"
#include <string>
#include <mutex>
#include <map>
#include <iostream>
#include "TLHelp32.h"
#include "ProcChnl.h"

#define MAX_CHANNEL_BUFF_SIZE 32 * 1024 * 1024

FILE* g_OutStream = NULL;
FILE* g_InStream = NULL;
std::mutex g_mtxCall;
BOOL	   g_stop = FALSE;
std::map<PVOID/*HOOK ADDR*/, PVOID/*OLD ADDR*/> g_mapHook;
TCHAR g_szPDBPath[256] = { 0 };
BOOL		g_bConsole = FALSE;
BOOL		g_bUtf8 = TRUE;
HCHANNEL g_hOutChnl = { 0 };

DWORD CMisc::GetExportFunctionsRva(HMODULE hModule, const char* strFuncName)
{
	// 获取ExportsTableRva
	DWORD dwExportTableRva = 0;
	PBYTE pByte = (PBYTE)hModule;
	PBYTE pTmp = pByte;
	if (IMAGE_DOS_SIGNATURE == *(WORD*)pTmp)
	{
		//DOS头
		IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pTmp;
		pTmp += pDosHeader->e_lfanew;
	}

	if (IMAGE_NT_SIGNATURE != *(DWORD*)(PBYTE)pTmp)
	{
		return 0;
	}

	pTmp += sizeof(DWORD);
	PIMAGE_FILE_HEADER pPEHeader = (PIMAGE_FILE_HEADER)pTmp;

	pTmp += sizeof(IMAGE_FILE_HEADER);
	// opt tou
	if (IMAGE_NT_OPTIONAL_HDR32_MAGIC == *(WORD*)(PBYTE)pTmp)
	{
		// 32位头
		dwExportTableRva = ((PIMAGE_OPTIONAL_HEADER32)pTmp)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}
	else if (IMAGE_NT_OPTIONAL_HDR64_MAGIC == *(WORD*)(PBYTE)pTmp)
	{
		// 32位头
		dwExportTableRva = ((PIMAGE_OPTIONAL_HEADER64)pTmp)->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}

	// 
	PIMAGE_EXPORT_DIRECTORY pExportDir = (PIMAGE_EXPORT_DIRECTORY)((PBYTE)pByte + dwExportTableRva);
	for (int i = 0; i < pExportDir->NumberOfNames; i++)
	{
		std::string strName = (char*)((PBYTE)pByte + *(DWORD*)((PBYTE)pByte + pExportDir->AddressOfNames + i * sizeof(DWORD)));

		if (strName == strFuncName)
		{
			WORD wOrdinal = *(WORD*)((PBYTE)pByte + pExportDir->AddressOfNameOrdinals + i * sizeof(WORD));
			if (wOrdinal < pExportDir->NumberOfFunctions)
			{
				return *(DWORD*)((PBYTE)pByte + pExportDir->AddressOfFunctions + wOrdinal * sizeof(DWORD));
			}
		}
	}

	return 0;
}

PVOID CMisc::GetExportFunctionsVa(const char* szModuleName, const char* szFuncName)
{
	HMODULE hMod = ::GetModuleHandleA(szModuleName);
	if (hMod == NULL)
	{
		DLL_TRACE(_T("Can not find %s!"), szModuleName);
		return NULL;
	}
	DWORD dwFuncRva = GetExportFunctionsRva(hMod, szFuncName);
	if (dwFuncRva == 0)
	{
		DLL_TRACE(_T("Can not find %s in %s!"), szFuncName, szModuleName);
		return NULL;
	}

	DLL_TRACE(_T("%s!%s : %llX!"), szModuleName, szFuncName, (PVOID)((PBYTE)hMod + dwFuncRva));

	return (PVOID)((PBYTE)hMod + dwFuncRva);
}

PVOID CMisc::FindModuleMemoryFromSection(PBYTE pSection, DWORD dwSectionSize, PBYTE pDataBase, DWORD dwSize)
{
	PVOID pFind = NULL;
	DWORD dwOffset = 0;
	do 
	{
		if (0 == memcmp(pSection + dwOffset, pDataBase, dwSize))
		{
			return pSection + dwOffset;
		}
		dwOffset++;
	} while (dwOffset < dwSectionSize);
	return NULL;
}

PVOID CMisc::FindModuleMemory(HMODULE hModule, PBYTE pDataBase, DWORD dwSize)
{
	//跳过头部,在段内搜索
	PBYTE pBase = (PBYTE)hModule;
	IMAGE_DOS_HEADER* pDosHeader = (IMAGE_DOS_HEADER*)pBase;
	if (IMAGE_DOS_SIGNATURE == pDosHeader->e_magic)
	{
		pBase += pDosHeader->e_lfanew;
	}

	if (IMAGE_NT_SIGNATURE == *(DWORD*)((PBYTE)pBase))
	{
		pBase += sizeof(DWORD);
		DWORD dwSectionNum = ((PIMAGE_FILE_HEADER)pBase)->NumberOfSections;
		DWORD dwOptSize = ((PIMAGE_FILE_HEADER)pBase)->SizeOfOptionalHeader;
		pBase += sizeof(IMAGE_FILE_HEADER);
		pBase += dwOptSize;

		PIMAGE_SECTION_HEADER pSectionHeader = (PIMAGE_SECTION_HEADER)(pBase);
		for (DWORD i = 0; i < dwSectionNum; i++)
		{
			PVOID pFind = FindModuleMemoryFromSection((PBYTE)hModule + pSectionHeader[i].VirtualAddress, pSectionHeader[i].Misc.VirtualSize, pDataBase, dwSize);
			if (pFind != NULL)
			{
				return pFind;
			}
		}
	}

	return NULL;
}

PVOID CMisc::FindMemory(PBYTE pDataBase, DWORD dwSize, const char* szModuleName /*= nullptr*/)
{
	if (szModuleName == nullptr)
	{
		// 获取全部快照
		HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(GetCurrentProcess()));
		if (INVALID_HANDLE_VALUE != hProcessSnap)
		{
			PVOID pFind = NULL;
			MODULEENTRY32 me = { sizeof(me) };
			BOOL bRet = Module32First(hProcessSnap, &me);
			while (TRUE == bRet)
			{
				pFind = FindModuleMemory((HMODULE)me.modBaseAddr, pDataBase, dwSize);
				if (pFind)
				{
					break;
				}
				bRet = Module32Next(hProcessSnap, &me);
			}

			CloseHandle(hProcessSnap);

			return pFind;
		}
	}
	else
	{
		HMODULE hMod = ::GetModuleHandleA(szModuleName);
		if (hMod == NULL)
		{
			DLL_TRACE(_T("Can not find %s!"), szModuleName);
			return NULL;
		}

		return FindModuleMemory(hMod, pDataBase, dwSize);
	}

	return NULL;
}


BOOL
CALLBACK MY_PSYM_ENUMERATESYMBOLS_CALLBACK(
	_In_ PSYMBOL_INFO pSymInfo,
	_In_ ULONG SymbolSize,
	_In_opt_ PVOID UserContext
	)
{
	FILE* pFile = (FILE*)UserContext;
	if (pFile)
	{
		TCHAR szTmp[MAX_SYM_NAME] = { 0 };
		_sntprintf_s(szTmp, sizeof(szTmp) / sizeof(TCHAR), _T("%s\n"), pSymInfo->Name);
		fwrite(szTmp, 1, sizeof(TCHAR) * (pSymInfo->NameLen + 1), pFile);
	}
	else
	{
		DLL_TRACE(_T("\t%s"), pSymInfo->Name);
	}
	return TRUE;
}

void CMisc::PrintModuleSymbols(PCTSTR szModuleName, PCSTR szSaveFile)
{
	HMODULE hMod = 0;
	HANDLE hProcess = 0;
	DWORD64 BaseOfDll = 0;
	PIMAGEHLP_SYMBOL pSymbol = NULL;
	PVOID pRet = NULL;
	FILE* pFile = NULL;

	DWORD Options = SymGetOptions();

	Options = Options & ~SYMOPT_UNDNAME;
	SymSetOptions(Options);

	if (szModuleName)
	{
		hMod = GetModuleHandle(szModuleName);
	}

	if (hMod == 0)
	{
		DLL_TRACE(_T("Cannot find module %s"), szModuleName);
		return;
	}

	do
	{
		hProcess = GetCurrentProcess();
		BOOL bRet = SymInitialize(hProcess, 0, FALSE);
		if (FALSE == bRet)
		{
			DLL_TRACE(_T("SymInitialize error ..."));
			break;
		}

		TCHAR SymbolPath[256];
		GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

		_tcscat_s(SymbolPath, _T(";"));
		_tcscat_s(SymbolPath, g_szPDBPath);

		SymSetSearchPath(hProcess, SymbolPath);

		TCHAR FileName[256];
		GetCurrentDirectory(sizeof(FileName) / sizeof(TCHAR), FileName);
		_tcscat_s(FileName, _T("\\"));
		_tcscat_s(FileName, szModuleName);
		BaseOfDll = SymLoadModuleEx(hProcess, NULL, FileName, NULL, (DWORD64)hMod, 0, NULL, 0);
		if (BaseOfDll == 0)
		{
			DLL_TRACE(_T("SymLoadModule %s error code:%d"), FileName, GetLastError());
			break;
		}

		if (szSaveFile)
		{
			if (0 != fopen_s(&pFile, szSaveFile, "wb"))
			{
				DLL_TRACE(_T("Open file:%s failed! code:%d"), szSaveFile, GetLastError());
				break;
			}
		}

		TCHAR szMask[256] = { 0 };
		_sntprintf_s(szMask, sizeof(szMask) / sizeof(TCHAR), _T("%s\n"), szModuleName);
		SymEnumSymbols(hProcess, BaseOfDll, szMask, MY_PSYM_ENUMERATESYMBOLS_CALLBACK, pFile);

	} while (false);

	if (BaseOfDll != 0)
	{
		BOOL bRet = SymUnloadModule(hProcess, BaseOfDll);
		if (bRet == FALSE)
		{
			DLL_TRACE(_T("SymUnloadModule Failed! err:%d"), GetLastError());
		}
		BaseOfDll = 0;
	}

	SymCleanup(hProcess);

	if (pFile)
	{
		fclose(pFile);
		pFile = nullptr;
	}
	return;
}

#define WM_CONFIG_SYMBOL WM_USER + 100
BOOL CMisc::InitConsole(HINSTANCE hIns)
{
	AllocConsole();
	if (TRUE == g_bUtf8)
	{
		SetConsoleOutputCP(CP_UTF8);
	}
	HWND hwnd = GetConsoleWindow();
	HMENU hmenu = GetSystemMenu(hwnd, false);
	RemoveMenu(hmenu, SC_CLOSE, MF_BYCOMMAND);

	//AppendMenu(hmenu, MF_BYPOSITION | MF_SEPARATOR, NULL, NULL);
	//AppendMenu(hmenu, MF_BYPOSITION, WM_CONFIG_SYMBOL, _T("符号路径"));

	HANDLE h = GetStdHandle(STD_INPUT_HANDLE);
	DWORD dwMode = 0;
	GetConsoleMode(h, &dwMode);
	// 代码禁用编辑，防止误点击卡主，如需要打开，可手动操作控制台菜单的属性打开
	dwMode &= ~ENABLE_QUICK_EDIT_MODE;	// 禁用快速编辑
	dwMode &= ~ENABLE_INSERT_MODE;		// 禁用插入
	dwMode &= ~ENABLE_MOUSE_INPUT;		// 禁用鼠标输入
	SetConsoleMode(h, dwMode);

	//freopen_s(&g_InStream, "CONIN$", "r", stdin);
	return 0 == freopen_s(&g_OutStream, "CONOUT$", "w", stdout);
}

#define DEBUG_SETTING_PATH _T(".\\GDebugInfo.ini")
BOOL CMisc::InitData()
{
	DWORD dwRet = ::GetPrivateProfileString(_T("Debug"), _T("PDB"), _T("."), g_szPDBPath, sizeof(g_szPDBPath) / sizeof(TCHAR), DEBUG_SETTING_PATH);
	g_bConsole = ::GetPrivateProfileInt(_T("Debug"), _T("Mode"), 0, DEBUG_SETTING_PATH) == 1 ? TRUE : FALSE;
	g_bUtf8 = ::GetPrivateProfileInt(_T("Debug"), _T("Code"), 1, DEBUG_SETTING_PATH) == 1 ? TRUE : FALSE;
	return dwRet > 0;
}

BOOL CMisc::UnInitConsole()
{
	if (g_OutStream)
	{
		fclose(g_OutStream);
		g_OutStream = NULL;
	}

	if (g_InStream)
	{
		fclose(g_InStream);
		g_InStream = NULL;
	}
	FreeConsole();
	return TRUE;
}

BOOL CMisc::InitSharedMemory()
{
	g_hOutChnl = ProcChnl::CreateChannel(_T("DllInject"), MAX_CHANNEL_BUFF_SIZE);
	return VALID_CHANNEL(g_hOutChnl);
}

BOOL CMisc::UnInitSharedMemory()
{
	if (!VALID_CHANNEL(g_hOutChnl))
	{
		return FALSE;
	}

	ProcChnl::CloseChannel(g_hOutChnl);
	return TRUE;
}

BOOL CMisc::BeginWork()
{
	g_mtxCall.lock();
	if (g_stop == TRUE)
	{
		g_mtxCall.unlock();
		return FALSE;
	}

	return TRUE;
}

BOOL CMisc::EndWork()
{
	g_mtxCall.unlock();
	return TRUE;
}

BOOL CMisc::StartWork(HINSTANCE hIns)
{
	InitData();
	if (TRUE == g_bConsole)
	{
		InitConsole(hIns);
	}
	else
	{
		InitSharedMemory();
	}

	return TRUE;
}

BOOL CMisc::StopWork()
{
	if (g_mapHook.size() > 0)
	{
		std::lock_guard<decltype(g_mtxCall)> lock(g_mtxCall);
		g_stop = TRUE;

		BEGIN_TRANSACTION;

		for (auto& item : g_mapHook)
		{
			DetourDetach(&item.second, item.first);
		}
		END_TRANSACTION;
	}
	if (TRUE == g_bConsole)
	{
		UnInitConsole();
	}
	else
	{
		UnInitSharedMemory();
	}

	return TRUE;
}

void CMisc::OnDetourAttach(std::function<PVOID(void)> fn, PVOID fnHook)
{
	std::lock_guard<decltype(g_mtxCall)> lock(g_mtxCall);
	if (g_mapHook.find(fnHook) == g_mapHook.end())
	{ 
		PVOID pOld = fn(); 
		if (pOld != NULL) 
		{
			g_mapHook[fnHook] = pOld;
			if (0 != DetourAttach(&g_mapHook[fnHook], fnHook))
			{
				g_mapHook.erase(fnHook);
				DLL_TRACE(_T("DetourAttach return Failed!"));
			}
		} 
	}
	else 
	{
		DLL_TRACE(_T("fnHook is aleady in use!"));
	}
}

#define MAX_LOG_BUFF_SIZE 1024 * 1024 * 32
void CMisc::WriteLog(LPCTSTR szFmt, ...)
{
	va_list ap;
	va_start(ap, szFmt);
	WriteLogV(szFmt, ap);
	va_end(ap);
}

void CMisc::WriteLogV(LPCTSTR szFmt, va_list _ArgList)
{
	if (g_bConsole)
	{
		_vtprintf(szFmt, _ArgList);
		_tprintf(_T("\r\n"));
	}
	else
	{
		TCHAR* pszTmp = new TCHAR[MAX_LOG_BUFF_SIZE] ;
		memset(pszTmp, 0, MAX_LOG_BUFF_SIZE * sizeof(TCHAR));
		int len = _vsntprintf_s(pszTmp, MAX_LOG_BUFF_SIZE, MAX_LOG_BUFF_SIZE - 3, szFmt, _ArgList);
		if (len < 0)
		{
			delete[]pszTmp;
			return;
		}

		pszTmp[len++] = _T('\r');
		pszTmp[len++] = _T('\n');
		//szTmp[len++] = '\0';
		if (TRUE == ProcChnl::CanWrite(g_hOutChnl, len))
		{
			ProcChnl::GWrite(g_hOutChnl, (char*)pszTmp, len);
		}

		delete[]pszTmp;
	}
}

PVOID CMisc::GetOldAddr(PVOID fnHook)
{
	if (g_mapHook.find(fnHook) == g_mapHook.end())
	{
		return NULL;
	}

	return g_mapHook[fnHook];
}

PVOID CMisc::GetFunctionsVaFromSymbols(PCTSTR szModuleName, PCTSTR szFunctionName, PCTSTR szSymPath/* = nullptr*/)
{
	HMODULE hMod = 0;
	HANDLE hProcess = 0;
	DWORD64 BaseOfDll = 0;
	PIMAGEHLP_SYMBOL pSymbol = NULL;
	PVOID pRet = NULL;

	DWORD Options = SymGetOptions();

	Options = Options | SYMOPT_DEBUG;
	SymSetOptions(Options);

	if (szModuleName)
	{
		hMod = GetModuleHandle(szModuleName);
	}

	if (hMod == 0)
	{
		DLL_TRACE(_T("Cannot find module %s"), szModuleName);
		return NULL;
	}

	do 
	{
		hProcess = GetCurrentProcess();
		BOOL bRet = SymInitialize(hProcess, 0, FALSE);
		if (FALSE == bRet)
		{
			DLL_TRACE(_T("SymInitialize error ..."));
			break;
		}
		TCHAR SymbolPath[256];
		GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

		if (nullptr != szSymPath)
		{
			_tcscat_s(SymbolPath, _T(";"));
			_tcscat_s(SymbolPath, szSymPath);
		}

		_tcscat_s(SymbolPath, _T(";"));
		_tcscat_s(SymbolPath, g_szPDBPath);

		SymSetSearchPath(hProcess, SymbolPath);

		TCHAR FileName[256];
		GetCurrentDirectory(sizeof(FileName) / sizeof(TCHAR), FileName);
		_tcscat_s(FileName, _T("\\"));
		_tcscat_s(FileName, szModuleName);
		BaseOfDll = SymLoadModuleEx(hProcess, NULL, FileName, NULL, (DWORD64)hMod, 0, NULL, 0);
		if (BaseOfDll == 0)
		{
			DLL_TRACE(_T("SymLoadModule %s error code:%d"), FileName, GetLastError());
			break;
		}

		ULONG64 buffer[(sizeof(SYMBOL_INFO) +
			MAX_SYM_NAME * sizeof(TCHAR) +
			sizeof(ULONG64) - 1) /
			sizeof(ULONG64)];
		PSYMBOL_INFO pSym = (PSYMBOL_INFO)buffer;
		pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSym->MaxNameLen = MAX_SYM_NAME;
		if (TRUE == SymFromName(hProcess, szFunctionName, pSym))
		{
			pRet = (PVOID)pSym->Address;
			DLL_TRACE(_T("%s!%s: %llX"), szModuleName, szFunctionName, pRet);
		}
		else
		{
			DLL_TRACE(_T("Can not find symbol %s!%s"), szModuleName, szFunctionName);
		}
	} while (false);

	if (BaseOfDll != 0)
	{
		BOOL bRet = SymUnloadModule(hProcess, BaseOfDll);
		if (bRet == FALSE)
		{
			DLL_TRACE(_T("SymUnloadModule Failed! err:%d"), GetLastError());
		}
		BaseOfDll = 0;
	}

	SymCleanup(hProcess);

	return pRet;
}

extern "C" void DoDebugWork();
extern "C" void EndDebugWork();

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		CMisc::StartWork(hModule);
		DoDebugWork();
	}
	break;
	case DLL_THREAD_ATTACH:
		break;
	case DLL_THREAD_DETACH:
		break;
	case DLL_PROCESS_DETACH:
	{
		CMisc::StopWork();
		EndDebugWork();
	}
	break;
	}
	return TRUE;
}

