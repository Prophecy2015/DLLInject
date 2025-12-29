#include "Misc.h"
#include "stdio.h"
#include <string>
#include <mutex>
#include <map>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <atomic>
#include "TLHelp32.h"
#include "ProcChnl.h"
#include "time.h"
#include "DbgHelper.h"

#define MAX_CHANNEL_BUFF_SIZE 32 * 1024 * 1024

FILE* g_OutStream = NULL;
FILE* g_InStream = NULL;
std::atomic<int> g_activeCall(0);
BOOL	   g_stop = FALSE;
std::map<PVOID/*HOOK ADDR*/, PVOID/*OLD ADDR*/> g_mapHook;
TCHAR g_szPDBPath[256] = { 0 };
BOOL		g_bConsole = FALSE;
BOOL		g_bUtf8 = TRUE;
HCHANNEL	g_hOutChnl = { 0 };
CDbgHelper  g_DbgHelper;
TCHAR		g_szAppPathName[256] = { 0 };

DWORD CMisc::GetExportFunctionsRva(HMODULE hModule, PCTSTR strFuncName)
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
	for (auto i = 0; i < pExportDir->NumberOfNames; i++)
	{
		std::string strName = (char*)((PBYTE)pByte + *(DWORD*)((PBYTE)pByte + pExportDir->AddressOfNames + i * sizeof(DWORD)));

		if (strName == TSTRCONV(strFuncName))
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

PVOID CMisc::GetExportFunctionsVa(PCTSTR szModuleName, PCTSTR szFuncName)
{
	HMODULE hMod = ::GetModuleHandle(szModuleName);
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
	_tstring strAppName = GetFileName(g_szAppPathName);

	DLL_TRACE(_T("%s!%s : %IX!"), szModuleName == nullptr ? strAppName.c_str() : szModuleName, szFuncName, (PVOID)((PBYTE)hMod + dwFuncRva));

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

PVOID CMisc::FindMemory(PBYTE pDataBase, DWORD dwSize, PCTSTR szModuleName /*= nullptr*/)
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
		HMODULE hMod = ::GetModuleHandle(szModuleName);
		if (hMod == NULL)
		{
			DLL_TRACE(_T("Can not find %s!"), szModuleName);
			return NULL;
		}

		return FindModuleMemory(hMod, pDataBase, dwSize);
	}

	return NULL;
}

_tstring CMisc::SymbolStrFromAddr(DWORD64 address, PCTSTR szSymPath /*= nullptr*/)
{
	if (!g_DbgHelper.Init())
	{
		DLL_TRACE(_T("Load DbgHelp.dll failed!"));
		return _T("");
	}

	_tstring strSymStr;
	constexpr int iBufferSize = sizeof(SYMBOL_INFO) + 256;
	char szBuffer[iBufferSize] = { 0 };

	TCHAR SymbolPath[256];
	GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

	_tcscat_s(SymbolPath, _T(";"));
	_tcscat_s(SymbolPath, g_szPDBPath);

	HANDLE hProcess = GetCurrentProcess();
	BOOL bRet = g_DbgHelper.m_pSymInitialize(hProcess, SymbolPath, TRUE);
	if (FALSE == bRet)
	{
		DLL_TRACE(_T("SymInitialize error ..."));
		return _T("");
	}

	do
	{
		SYMBOL_INFO* pInfo = (SYMBOL_INFO*)szBuffer;
		pInfo->MaxNameLen = 256;

		if (FALSE == g_DbgHelper.m_pSymFromAddr(hProcess, address, 0, pInfo))
		{
			DLL_TRACE(_T("SymFromAddr(%p) failed ..."), address);
			break;
		}

		strSymStr = pInfo->Name;

	} while (false);

	g_DbgHelper.m_pSymCleanup(hProcess);

	return strSymStr;
}

_tstring CMisc::AddrModuleName(DWORD64 address)
{
	HMODULE handle;
	if (FALSE == GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS, (LPCTSTR)address, &handle))
	{
		DLL_TRACE(_T("GetModuleHandleExA(%p) failed(0x%X) ..."), address, GetLastError());
		return _T("");
	}

	TCHAR szFileName[MAX_PATH] = { 0 };
	if (0 == GetModuleFileName(handle, szFileName, MAX_PATH))
	{
		DLL_TRACE(_T("GetModuleFileNameA(%p) failed ..."), handle);
		return _T("");
	}

	DLL_TRACE(_T("AddrModuleName(%p) = %s"), address, szFileName);
	return szFileName;
}

void CMisc::ShowTraceStarck()
{
	if (!g_DbgHelper.Init())
	{
		DLL_TRACE(_T("Load DbgHelp.dll failed!"));
		return ;
	}
	constexpr int MAX_STACK_FRAMES = 12;
	constexpr int FRAME_INFO_LEN = 2048;
	constexpr int STACK_INFO_LEN = FRAME_INFO_LEN * MAX_STACK_FRAMES;
	void *pStack[MAX_STACK_FRAMES];
	static TCHAR szStackInfo[STACK_INFO_LEN] = { 0 };
	static TCHAR szFrameInfo[FRAME_INFO_LEN] = { 0 };

	DWORD Options = g_DbgHelper.m_pSymGetOptions();

	Options = Options | SYMOPT_LOAD_LINES;
	g_DbgHelper.m_pSymSetOptions(Options);

	TCHAR SymbolPath[256] = { 0 };
	GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

	_tcscat_s(SymbolPath, _T(";"));
	_tcscat_s(SymbolPath, g_szPDBPath);
	HANDLE hProcess = GetCurrentProcess();
	BOOL bRet = g_DbgHelper.m_pSymInitialize(hProcess, SymbolPath, TRUE);
	if (FALSE == bRet)
	{
		DLL_TRACE(_T("SymInitialize error ..."));
		return;
	}

	WORD frames = CaptureStackBackTrace(0, MAX_STACK_FRAMES, pStack, NULL);
	_sntprintf_s(szStackInfo, FRAME_INFO_LEN - 1, _T("stack traceback:%d\n"), frames);

	for (WORD i = 0; i < frames; ++i) {
		DWORD64 address = (DWORD64)(pStack[i]);

		DWORD64 displacementSym = 0;
		SYMBOL_INFO_PACKAGE stSymbolInfo = { 0 };
		stSymbolInfo.si.SizeOfStruct = sizeof(SYMBOL_INFO);
		stSymbolInfo.si.MaxNameLen = MAX_SYM_NAME;

		DWORD displacementLine = 0;
		IMAGEHLP_LINE line = { sizeof(line) };

		if (TRUE == g_DbgHelper.m_pSymFromAddr(hProcess, address, &displacementSym, &stSymbolInfo.si))
		{
			if (TRUE == g_DbgHelper.m_pSymGetLineFromAddr(hProcess, address, &displacementLine, &line))
			{
				_sntprintf_s(szFrameInfo, FRAME_INFO_LEN - 1, _T("\t0x%IX %s() at %s:%d\n"),
					stSymbolInfo.si.Address, stSymbolInfo.si.Name, line.FileName, line.LineNumber);
			}
			else
			{
				_sntprintf_s(szFrameInfo, FRAME_INFO_LEN - 1, _T("\t0x%IX %s()\n"), stSymbolInfo.si.Address, stSymbolInfo.si.Name);
			}
		}
		else
		{
			_sntprintf_s(szFrameInfo, FRAME_INFO_LEN - 1, _T("\t0x%IX can not find symbol\n"), address);
		}

		_tcscat_s(szStackInfo, szFrameInfo);
	}
	g_DbgHelper.m_pSymCleanup(hProcess);

	DLL_TRACE(_T("%s"), szStackInfo);
}


void CMisc::ShowContextStackTrace(CONTEXT& cr)
{
	if (!g_DbgHelper.Init())
	{
		DLL_TRACE(_T("Load DbgHelp.dll failed!"));
		return;
	}

	if (!g_DbgHelper.m_pStackWalk ||
		!g_DbgHelper.m_pSymFunctionTableAccess ||
		!g_DbgHelper.m_pSymGetModuleBase)
	{
		printf("DbgHelp.dll Leak interface!");
		return;
	}

	TCHAR SymbolPath[256] = { 0 };
	GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

	_tcscat_s(SymbolPath, _T(";"));
	_tcscat_s(SymbolPath, g_szPDBPath);

	auto hProcess = GetCurrentProcess();
	auto hThread = GetCurrentThread();
	g_DbgHelper.m_pSymInitialize(hProcess, SymbolPath, TRUE);

	DWORD dwMachineType = IMAGE_FILE_MACHINE_UNKNOWN;

	STACKFRAME sf = { 0 };
#ifdef _IMAGEHLP64
	dwMachineType = IMAGE_FILE_MACHINE_AMD64;
	sf.AddrPC.Offset = cr.Rip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = cr.Rbp;
	sf.AddrFrame.Mode = AddrModeFlat;
	sf.AddrStack.Offset = cr.Rsp;
	sf.AddrStack.Mode = AddrModeFlat;
#else
	dwMachineType = IMAGE_FILE_MACHINE_I386;
	sf.AddrPC.Offset = cr.Eip;
	sf.AddrPC.Mode = AddrModeFlat;
	sf.AddrFrame.Offset = cr.Ebp;
	sf.AddrFrame.Mode = AddrModeFlat;
	sf.AddrStack.Offset = cr.Esp;
	sf.AddrStack.Mode = AddrModeFlat;
#endif

	while (g_DbgHelper.m_pStackWalk(dwMachineType, hProcess, hThread, &sf, &cr, 0, g_DbgHelper.m_pSymFunctionTableAccess, g_DbgHelper.m_pSymGetModuleBase, nullptr))
	{
		auto address = sf.AddrPC.Offset;
		DWORD64 dwDisplacement = 0;
		SYMBOL_INFO_PACKAGE symbol = { 0 };
		symbol.si.SizeOfStruct = sizeof(symbol.si);
		symbol.si.MaxNameLen = sizeof(symbol.name) / sizeof(TCHAR);
		if (g_DbgHelper.m_pSymFromAddr && TRUE == g_DbgHelper.m_pSymFromAddr(hProcess, address, &dwDisplacement, &symbol.si))
		{
			DWORD dwLineDisplacement = 0;
			IMAGEHLP_LINE line = { sizeof(line) };
			if (g_DbgHelper.m_pSymGetLineFromAddr && TRUE == g_DbgHelper.m_pSymGetLineFromAddr(hProcess, address, &dwLineDisplacement, &line))
			{
				_tprintf(_T("\t%IX %s + %Id(%s:%u)\n"), address, symbol.si.Name, dwDisplacement, line.FileName, line.LineNumber);
			}
			else
			{
				_tprintf(_T("\t%IX %s + %Id\n"), address, symbol.si.Name, dwDisplacement);
			}
		}
		else
		{
			_tprintf(_T("\t%IX Cannot find symbol!\n"), address);
		}
	}

	g_DbgHelper.m_pSymCleanup(hProcess);
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
		_sntprintf_s(szTmp, MAX_SYM_NAME - 1, _T("%s\n"), pSymInfo->Name);
		fwrite(szTmp, 1, pSymInfo->NameLen + 1, pFile);
	}
	else
	{
		DLL_TRACE(_T("\t%s"), pSymInfo->Name);
	}
	return TRUE;
}

void CMisc::PrintModuleSymbols(PCTSTR szModuleName, PCTSTR szSaveFile)
{
	if (!g_DbgHelper.Init())
	{
		DLL_TRACE(_T("Load DbgHelp.dll failed!"));
		return;
	}

	HMODULE hMod = 0;
	HANDLE hProcess = 0;
	DWORD64 BaseOfDll = 0;
	PIMAGEHLP_SYMBOL pSymbol = NULL;
	PVOID pRet = NULL;
	FILE* pFile = NULL;

	DWORD Options = g_DbgHelper.m_pSymGetOptions();

	Options = Options & ~SYMOPT_UNDNAME;
	g_DbgHelper.m_pSymSetOptions(Options);

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

		TCHAR SymbolPath[256];
		GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

		_tcscat_s(SymbolPath, _T(";"));
		_tcscat_s(SymbolPath, g_szPDBPath);

		hProcess = GetCurrentProcess();
		BOOL bRet = g_DbgHelper.m_pSymInitialize(hProcess, SymbolPath, FALSE);
		if (FALSE == bRet)
		{
			DLL_TRACE(_T("SymInitialize error ..."));
			break;
		}

		BaseOfDll = g_DbgHelper.m_pSymLoadModule(hProcess, NULL, TSTRCONV(g_szAppPathName).c_str(), TSTRCONV(szModuleName).c_str(), (DWORD64)hMod, 0);
		if (BaseOfDll == 0)
		{
			DLL_TRACE(_T("SymLoadModule %s error code:%d"), szModuleName, GetLastError());
			break;
		}

		if (szSaveFile)
		{
			if (0 != _tfopen_s(&pFile, szSaveFile, _T("wb")))
			{
				DLL_TRACE(_T("Open file:%s failed! code:%d"), szSaveFile, GetLastError());
				break;
			}
		}

		TCHAR szMask[256] = { 0 };
		_sntprintf_s(szMask, sizeof(szMask) / sizeof(TCHAR) - 1, _T("%s\n"), szModuleName);
		g_DbgHelper.m_pSymEnumSymbols(hProcess, BaseOfDll, szMask, MY_PSYM_ENUMERATESYMBOLS_CALLBACK, pFile);

	} while (false);

	if (BaseOfDll != 0)
	{
		BOOL bRet = g_DbgHelper.m_pSymUnloadModule(hProcess, BaseOfDll);
		if (bRet == FALSE)
		{
			DLL_TRACE(_T("SymUnloadModule Failed! err:%d"), GetLastError());
		}
		BaseOfDll = 0;
	}

	g_DbgHelper.m_pSymCleanup(hProcess);

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

BOOL CMisc::InitSharedMemory(LPCTSTR szName)
{
	g_hOutChnl = ProcChnl::CreateChannel(szName, MAX_CHANNEL_BUFF_SIZE);
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
	g_activeCall++;
	if (g_stop == TRUE)
	{
		g_activeCall--;
		return FALSE;
	}

	return TRUE;
}

BOOL CMisc::EndWork()
{
	g_activeCall--;
	return TRUE;
}

BOOL CMisc::StartWork(HINSTANCE hIns)
{
	EnablePrivilegeDebug(true);
	GetModuleFileName(0, g_szAppPathName, sizeof(g_szAppPathName) / sizeof(TCHAR));

	InitData();
	if (TRUE == g_bConsole)
	{
		InitConsole(hIns);
	}
	else
	{
		TCHAR szFileName[MAX_PATH] = { 0 };
		auto dwRet = GetModuleFileName(hIns, szFileName, MAX_PATH);
		if (dwRet == 0)
		{
			DLL_TRACE(_T("GetModuleFileName Failed!"));
			return FALSE;
		}

		InitSharedMemory(GetFileNameWithOutExt(szFileName).c_str());
	}

	return TRUE;
}

BOOL CMisc::StopWork()
{
	if (g_mapHook.size() > 0)
	{
		g_stop = TRUE;
		while (g_activeCall > 0)
		{
			std::this_thread::sleep_for(std::chrono::milliseconds(20));
		}

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

	EnablePrivilegeDebug(false);
	return TRUE;
}

void CMisc::OnDetourAttach(std::function<PVOID(void)> fn, PVOID fnHook)
{
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
	_tstring strTime = GetNowTimeStr();
	if (g_bConsole)
	{
		_tprintf(_T("[%s]"), strTime.c_str());
		_vtprintf(szFmt, _ArgList);
		_tprintf(_T("\r\n"));
	}
	else
	{
		TCHAR* szTmp = new TCHAR[MAX_LOG_BUFF_SIZE];
		int iOff = _sntprintf_s(szTmp, MAX_LOG_BUFF_SIZE - 1, MAX_LOG_BUFF_SIZE, _T("[%s]"), strTime.c_str());
		if (iOff < 0)
		{
			delete[]szTmp;
			return;
		}

		int len = _vsntprintf_s(szTmp + iOff, MAX_LOG_BUFF_SIZE - iOff - 3, MAX_LOG_BUFF_SIZE - iOff - 2, szFmt, _ArgList);
		if (len < 0)
		{
			delete[]szTmp;
			return;
		}

		len += iOff;

		szTmp[len++] = _T('\r');
		szTmp[len++] = _T('\n');
		//szTmp[len++] = '\0';
		if (TRUE == ProcChnl::CanWrite(g_hOutChnl, len * sizeof(TCHAR)))
		{
			ProcChnl::GWrite(g_hOutChnl, (unsigned char*)szTmp, len * sizeof(TCHAR));
		}
		delete[]szTmp;
	}
}

_tstring CMisc::GetNowTimeStr()
{
	_tstring strTimeStr;
	auto n = std::chrono::system_clock::now();
	time_t now_t = std::chrono::system_clock::to_time_t(n);
	tm now_tm;
	localtime_s(&now_tm, &now_t);

	TCHAR szTime[64] = { 0 };
	_tcsftime(szTime, sizeof(szTime) / sizeof(TCHAR), _T("%F %T"), &now_tm);
	strTimeStr = szTime;

	TCHAR szMsTime[16] = { 0 };
	auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(n.time_since_epoch()) % 1000;
	int iSize =_sntprintf_s(szMsTime, sizeof(szMsTime) / sizeof(TCHAR) - 1, _T(":%Id"), ms.count());
	strTimeStr += szMsTime;

	return strTimeStr;
}

std::string CMisc::W2M(const std::wstring& wstr)
{
	auto iSize = WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), NULL, 0, NULL, NULL);
	char* pszMultiByte = new char[iSize];
	memset(pszMultiByte, 0, iSize);
	WideCharToMultiByte(CP_ACP, 0, wstr.c_str(), wstr.size(), pszMultiByte, iSize, NULL, NULL);
	std::string strMultiByte = pszMultiByte;
	delete[]pszMultiByte;
	return strMultiByte;
}

std::wstring CMisc::M2W(const std::string& str)
{
	auto iSize = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
	wchar_t* pszWideChar = new wchar_t[iSize];
	wmemset(pszWideChar, 0, iSize);
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), str.size(), pszWideChar, iSize);
	std::wstring strWideChar = pszWideChar;
	delete[]pszWideChar;
	return strWideChar;
}

_tstring CMisc::GetFileName(_tstring strFilePathName)
{
	int iPos = strFilePathName.find_last_of(_T("\\"));
	if (iPos != _tstring::npos)
	{
		return _tstring(strFilePathName.c_str() + iPos + 1);
	}
	return strFilePathName;
}

_tstring CMisc::GetFileNameWithOutExt(_tstring strFilePathName)
{
	int iPos1 = strFilePathName.find_last_of(_T("\\"));
	int iPos2 = strFilePathName.find_last_of(_T("."));
	if (iPos1 == _tstring::npos &&
		iPos2 == _tstring::npos)
	{
		return strFilePathName;
	}
	else if (iPos2 == _tstring::npos)
	{
		return _tstring(strFilePathName.c_str() + iPos1 + 1);
	}
	else if (iPos1 == _tstring::npos)
	{
		return _tstring(strFilePathName.c_str(), iPos2 -1);
	}
	else if (iPos2 > iPos1)
	{
		return _tstring(strFilePathName.c_str() + iPos1 + 1, iPos2 - iPos1 - 1);
	}

	return strFilePathName;
}

_tstring CMisc::FormatHex(BYTE * buf, int len)
{
	_tstring tt;
	for (int i = 0; i < len; ++i) {
		TCHAR temp[4] = { 0 };
		_sntprintf_s(temp, 4, _T("%02X "), buf[i]);
		tt.append(temp);
	}
	return tt;
}

BOOL CMisc::EnablePrivilegeDebug(BOOL bEnable)
{
	BOOL bRet = FALSE;
	HANDLE hToken;
	if (FALSE == OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))
	{
		return FALSE;
	}
	TOKEN_PRIVILEGES tp;
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = bEnable ? SE_PRIVILEGE_ENABLED : 0;
	if (TRUE == LookupPrivilegeValue(NULL, SE_CREATE_GLOBAL_NAME, &tp.Privileges[0].Luid)) {
		bRet = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
		if (FALSE == bRet)
		{
			printf("AdjustTokenPrivileges FALSE = %u", GetLastError());
		}
	}

	CloseHandle(hToken);

	return bRet;
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
	if (!g_DbgHelper.Init())
	{
		DLL_TRACE(_T("Load DbgHelp.dll failed!"));
		return nullptr;
	}

	HANDLE hProcess = 0;
	DWORD64 BaseOfDll = 0;
	PIMAGEHLP_SYMBOL pSymbol = NULL;
	PVOID pRet = NULL;

	_tstring strAppName = GetFileName(g_szAppPathName);

	DWORD Options = g_DbgHelper.m_pSymGetOptions();

	Options = Options | SYMOPT_DEBUG;
	g_DbgHelper.m_pSymSetOptions(Options);

	do 
	{
		TCHAR SymbolPath[256];
		GetCurrentDirectory(sizeof(SymbolPath) / sizeof(TCHAR), SymbolPath);

		if (nullptr != szSymPath)
		{
			_tcscat_s(SymbolPath, _T(";"));
			_tcscat_s(SymbolPath, szSymPath);
		}

		_tcscat_s(SymbolPath, _T(";"));
		_tcscat_s(SymbolPath, g_szPDBPath);

		hProcess = GetCurrentProcess();
		BOOL bRet = g_DbgHelper.m_pSymInitialize(hProcess, SymbolPath, FALSE);
		if (FALSE == bRet)
		{
			DLL_TRACE(_T("SymInitialize error ..."));
			break;
		}

		std::string strLoadModule;
		HMODULE hMod = NULL;
		if (nullptr != szModuleName)
		{
			strLoadModule = TSTRCONV(szModuleName);
			hMod = GetModuleHandle(szModuleName);
			if (hMod == 0)
			{
				DLL_TRACE(_T("Cannot find module %s"), szModuleName);
				break;
			}
		}
		else
		{
			strLoadModule = TSTRCONV(strAppName);
			hMod = GetModuleHandle(strAppName.c_str());
			if (hMod == 0)
			{
				DLL_TRACE(_T("Cannot find module %s"), strAppName.c_str());
				break;
			}
		}

		BaseOfDll = g_DbgHelper.m_pSymLoadModule(hProcess, NULL, TSTRCONV(g_szAppPathName).c_str(), strLoadModule.c_str(), (DWORD64)hMod, 0);
		if (BaseOfDll == 0)
		{
			DLL_TRACE(_T("SymLoadModule %s error code:%d"), szModuleName, GetLastError());
			break;
		}

		ULONG64 buffer[(sizeof(SYMBOL_INFO) +
			MAX_SYM_NAME * sizeof(TCHAR) +
			sizeof(ULONG64) - 1) /
			sizeof(ULONG64)];
		PSYMBOL_INFO pSym = (PSYMBOL_INFO)buffer;
		pSym->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSym->MaxNameLen = MAX_SYM_NAME;
		if (TRUE == g_DbgHelper.m_pSymFromName(hProcess, szFunctionName, pSym))
		{
			pRet = (PVOID)pSym->Address;
			DLL_TRACE(_T("%s!%s: %IX"), szModuleName ? szModuleName : strAppName.c_str(), szFunctionName, pRet);
		}
		else
		{
			DLL_TRACE(_T("Can not find symbol %s!%s"), szModuleName ? szModuleName : strAppName.c_str(), szFunctionName);
		}
	} while (false);

	if (BaseOfDll != 0)
	{
		BOOL bRet = g_DbgHelper.m_pSymUnloadModule(hProcess, BaseOfDll);
		if (bRet == FALSE)
		{
			DLL_TRACE(_T("SymUnloadModule Failed! err:%d"), GetLastError());
		}
		BaseOfDll = 0;
	}

	g_DbgHelper.m_pSymCleanup(hProcess);

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

