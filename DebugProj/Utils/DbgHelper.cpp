#include "DbgHelper.h"		
#include "tchar.h"					

CDbgHelper::CDbgHelper()
	: m_hDLL(NULL)
	, m_pSymInitialize(nullptr)
	, m_pSymCleanup(nullptr)
	, m_pSymFromAddr(nullptr)
	, m_pSymGetLineFromAddr(nullptr)
	, m_pSymLoadModule(nullptr)
	, m_pSymUnloadModule(nullptr)
	, m_pStackWalk(nullptr)
	, m_pSymFunctionTableAccess(nullptr)
	, m_pSymGetModuleBase(nullptr)
	, m_pSymGetOptions(nullptr)
	, m_pSymSetOptions(nullptr)
	, m_pSymFromName(nullptr)
	, m_pSymEnumSymbols(nullptr)
{
}

CDbgHelper::~CDbgHelper()
{
	Uninit();
}

bool CDbgHelper::Init(LPCTSTR tsDLLPath)
{
	if (m_hDLL != NULL)
	{
		return true;
	}

	if (nullptr == tsDLLPath)
	{
		m_hDLL = LoadLibrary(_T("DbgHelp.dll"));
	}
	else
	{
		m_hDLL = LoadLibrary(tsDLLPath);
	}

	if (NULL == m_hDLL)
	{
		return false;
	}

	do
	{
		GDB_GETPROCADDRESS(SymInitialize);
		GDB_GETPROCADDRESS(SymCleanup);

		GDB_GETPROCADDRESS(SymFromAddr);
		GDB_GETPROCADDRESS(SymGetLineFromAddr);
		GDB_GETPROCADDRESS(SymLoadModule);
		GDB_GETPROCADDRESS(SymUnloadModule);
		GDB_GETPROCADDRESS(StackWalk);
		GDB_GETPROCADDRESS(SymFunctionTableAccess);
		GDB_GETPROCADDRESS(SymGetModuleBase);
		GDB_GETPROCADDRESS(SymGetOptions);
		GDB_GETPROCADDRESS(SymSetOptions);
		GDB_GETPROCADDRESS(SymFromName);
		GDB_GETPROCADDRESS(SymEnumSymbols);

		if (!m_pSymInitialize ||
			!m_pSymCleanup)
		{
			break;
		}

		return true;
	} while (false);

	Uninit();

	return false;
}

bool CDbgHelper::Uninit()
{
	if (NULL == m_hDLL)
	{
		return false;
	}

	FreeLibrary(m_hDLL);
	m_hDLL = nullptr;

	m_pSymInitialize= nullptr;
	m_pSymCleanup= nullptr;
	m_pSymFromAddr= nullptr;
	m_pSymGetLineFromAddr= nullptr;
	m_pSymLoadModule= nullptr;
	m_pSymUnloadModule= nullptr;
	m_pStackWalk= nullptr;
	m_pSymFunctionTableAccess= nullptr;
	m_pSymGetModuleBase= nullptr;
	m_pSymGetOptions = nullptr;
	m_pSymSetOptions = nullptr;
	m_pSymFromName = nullptr;
	m_pSymEnumSymbols = nullptr;

	return true;
}