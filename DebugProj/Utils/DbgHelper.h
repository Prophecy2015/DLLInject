#pragma once
#include "windows.h"

#ifdef _UNICODE
#define DBGHELP_TRANSLATE_TCHAR
#endif

#include "DbgHelp.h"

#define GDB_DECLTYPE(S) decltype(S)*
#define GDB_DECLARATION(S) GDB_DECLTYPE(S) m_p##S
#define GDB_GETPROCADDRESS_IN(S) GetProcAddress(m_hDLL, #S)
#define GDB_GETPROCADDRESS(S) m_p##S = (decltype(m_p##S))GDB_GETPROCADDRESS_IN(S)		



class CDbgHelper
{
public:
	CDbgHelper();
	~CDbgHelper();
public:
	bool Init(LPCTSTR tsDLLPath = nullptr);
	bool Uninit();
public:
	HMODULE			m_hDLL;
	GDB_DECLARATION(SymInitialize);
	GDB_DECLARATION(SymCleanup);
	GDB_DECLARATION(SymFromAddr);
	GDB_DECLARATION(SymGetLineFromAddr);
	GDB_DECLARATION(SymLoadModule);
	GDB_DECLARATION(SymUnloadModule);
	GDB_DECLARATION(StackWalk);
	GDB_DECLARATION(SymFunctionTableAccess);
	GDB_DECLARATION(SymGetModuleBase);
	GDB_DECLARATION(SymGetOptions);
	GDB_DECLARATION(SymSetOptions);
	GDB_DECLARATION(SymFromName);
	GDB_DECLARATION(SymEnumSymbols);
};