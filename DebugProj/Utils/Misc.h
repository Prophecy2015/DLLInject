#pragma once
#include <windows.h>
#include <functional>
#include <iostream>
#include "detours.h"
#include "tchar.h"
#include <string>
#include <chrono>

#ifndef NDEBUG
#pragma comment(lib, "detoursd.lib")
#pragma comment(lib, "Utils_d.lib")
#else
#pragma comment(lib, "detours.lib")
#pragma comment(lib, "Utils.lib")
#endif

#ifndef LLONG
#ifdef _WIN64
#define LLONG   INT64
#else 
#define LLONG   LONG
#endif
#endif

#ifdef _UNICODE
#define _tstring std::wstring 
#define TSTRCONV(s) W2M(s)
#else
#define _tstring std::string
#define TSTRCONV(s) std::string(s)
#endif

#ifndef LDWORD
#if (defined(WIN32) || defined(_WIN32) || defined(_WIN64))
#ifdef _WIN64
#define LDWORD  __int64
#else //WIN32 
#define LDWORD  DWORD
#endif
#else    //linux
#define LDWORD      long 
#endif
#endif

#define VFTABLE(c) ((PVOID)*(int64_t*)c)
#define VFTABLE_FUNC_ADDR(vftable, idx) (*((PVOID*)vftable + idx))
#define VFTABLE_FUNC(fnType, cls, idx) ((fnType)VFTABLE_FUNC_ADDR(VFTABLE(cls), idx))

#define BEGIN_TRANSACTION \
	DetourTransactionBegin();\
	DetourUpdateThread(GetCurrentThread());

#define END_TRANSACTION \
	DetourTransactionCommit();

#define CALL_OLD(x) ((decltype(&x))CMisc::GetOldAddr(x))

#define DLL_TRACE CMisc::WriteLog

#define CHECK_MEMORY_RET_NULL(x) \
DLL_TRACE("%s:%p", #x, x); \
if (x == NULL) \
{ \
	DLL_TRACE("ERR:%s is NULL!", #x); \
	return NULL; \
}

#define CHECK_MEMORY_RET_VOID(x) \
DLL_TRACE("%s:%p", #x, x); \
if (x == NULL) \
{ \
	DLL_TRACE("ERR:%s is NULL!", #x); \
	return; \
}

#define CUSTOM_SYMBOL_PATH ".;D:\\32055\\pdb" //���·���Էֺŷָ�
#define DEBUG_SETTING_PATH _T(".\\GDebugInfo.ini")

#define REF(t) PVOID
#define POINTER(t) PVOID
#define THIS_OBJ PVOID

template<typename T>
T GetValue(PVOID p)
{
	return *(T*)(p);
}

class CMisc
{
public:
	typedef std::function<PVOID(void)> TargetFunction;
public:
	// VA API
	/**
	* \brief ͨ������pdb�ļ������ڲ��������Ʋ��Ҷ��������ַ����Ҫpdb�ļ�֧�֣���������ʧ��
	* \param szModuleName ģ������
	* \param szFunctionName ��Ҫ���ҵĺ�������
	* \param szSymPath PDB�ļ�����·��������Ĭ��exe��ǰ·������
	* \return �����ҳɹ������غ��������ڵ�ǰ���������ַ��������ʧ�ܣ��򷵻�NULL
	*/ 
	static PVOID GetFunctionsVaFromSymbols(PCTSTR szModuleName, PCTSTR szFunctionName, PCTSTR szSymPath = nullptr);

	/**
	* \brief ͨ�����������Һ�����������ַ RVA
	* \param hModule ģ����(��ʵ����ģ���ڽ����м��ص������ַ)
	* \param strFuncName ������������
	* \return �����ҳɹ������غ��������ڵ�ǰ������������ַ��������ʧ�ܣ��򷵻�0
	*/
	static DWORD GetExportFunctionsRva(HMODULE hModule, PCTSTR strFuncName);

	/**
	* \brief ͨ�����������Һ��������ַ VA
	* \param szModuleName ģ������
	* \param strFuncName ������������
	* \return �����ҳɹ������غ��������ڵ�ǰ���������ַ��������ʧ�ܣ��򷵻�NULL
	* \note �ú�����Ե������ţ����ԣ�����û��pdb�ļ���ֻҪ������ģ��ĵ������У������Բ�ѯ�����������ǣ�ֻ�ܲ��ҵ����Ľӿڣ��ڲ��ӿ��޷�ʹ�øú���
	*/
	static PVOID GetExportFunctionsVa(PCTSTR szModuleName, PCTSTR szFuncName);

	/**
	* \brief �ڶ��ڲ��ҷ���ָ���ڴ�����ݵ������ַ
	* \param pSection �������ַ
	* \param dwSectionSize �δ�С
	* \param pDataBase �����������ڴ��
	* \param dwSize �����ڴ���С
	* \return �����ҳɹ�������ָ���ڴ���ڵ�ǰ�����е������ַ��������ʧ�ܣ��򷵻�NULL
	* \note �ú����Զ���������ƥ�������ַ����Ҫ����hook everywhere,hook����λ��ʹ�ã����ǣ������׵��µ��Խ��̱��������á�
	*/
	static PVOID FindModuleMemoryFromSection(PBYTE pSection, DWORD dwSectionSize, PBYTE pDataBase, DWORD dwSize);

	/**
	* \brief ��ָ��ģ���в��ҷ���ָ���ڴ�����ݵ������ַ
	* \param hModule �����ҵ�ģ����
	* \param pDataBase �����������ڴ��
	* \param dwSize �����ڴ���С
	* \return �����ҳɹ�������ָ���ڴ���ڵ�ǰ�����е������ַ��������ʧ�ܣ��򷵻�NULL
	* \note �ú����Զ���������ƥ�������ַ����Ҫ���ڶ�λ����λ��ʹ�ã����ǣ���λ�õ�ַ�Ĳ��������׵��µ��Խ��̱���������.
	*/
	static PVOID FindModuleMemory(HMODULE hModule, PBYTE pDataBase, DWORD dwSize);

	/**
	* \brief ���ҷ���ָ���ڴ�����ݵ������ַ
	* \param pDataBase �����������ڴ��
	* \param dwSize �����ڴ���С
	* \param szModuleName ����ָ��ģ������
	* \return �����ҳɹ�������ָ���ڴ���ڵ�ǰ�����е������ַ��������ʧ�ܣ��򷵻�NULL
	* \note �ú����Զ���������ƥ�������ַ����Ҫ���ڶ�λ����λ��ʹ�ã����ǣ���λ�õ�ַ�Ĳ��������׵��µ��Խ��̱��������á�
	*/
	static PVOID FindMemory(PBYTE pDataBase, DWORD dwSize, PCTSTR szModuleName = nullptr);

	/**
	* \brief ��ȡָ����ַ�ķ������ƣ����ܻ�ȡʧ��
	* \param address ��ַ
	* \param szSymPath �����ļ�·��
	* \return �����ҳɹ�������ָ����ַ�ķ������ƣ����򷵻ؿ�
	*/
	static _tstring SymbolStrFromAddr(DWORD64 address, PCTSTR szSymPath = nullptr);

	/**
	* \brief ��ȡָ����ַ���ڵ�ģ������
	* \param address ��ַ
	* \return �����ҳɹ�������ģ�����ƣ����򷵻ؿ�
	*/
	static _tstring AddrModuleName(DWORD64 address);

	/**
	* \brief ��ʾ��ǰ����ջ
	* \return void
	*/
	static void ShowTraceStarck();

	/**
	* \brief ��ʾָ�������ĵĶ�ջ
	* \return void
	*/
	static void ShowContextStackTrace(CONTEXT& cr);

	// Utils
	// ��ӡĳ��ģ������з���
	static void PrintModuleSymbols(PCTSTR szModuleName, PCTSTR szSaveFile = nullptr);

	// ����̨��ʼ��
	static BOOL InitConsole(HINSTANCE hIns);
	static BOOL UnInitConsole();
	// �����ڴ��ʼ��
	static BOOL InitSharedMemory(LPCTSTR szName);
	static BOOL UnInitSharedMemory();

	// HOOK
	static BOOL InitData();
	static BOOL BeginWork();
	static BOOL EndWork();
	static BOOL StartWork(HINSTANCE hIns);
	static BOOL StopWork();

	static PVOID GetOldAddr(PVOID fnHook);
	// Attach ���Ӻ��� 
	static void OnDetourAttach(std::function<PVOID(void)> fn, PVOID fnHook);

	static void WriteLog(LPCTSTR szFmt, ...);

	static void WriteLogV(LPCTSTR szFmt, va_list _ArgList);

	static _tstring GetNowTimeStr();

	static std::string W2M(const std::wstring&);

	static std::wstring M2W(const std::string&);

	static _tstring GetFileName(_tstring strFilePathName);

	static _tstring GetFileNameWithOutExt(_tstring strFilePathName);
};

// ͨ��PDB�������ؽӿ�
// m ģ������
// s ��������
// fnHook ���Ӻ���
#define DETOUR_ATTACH_SYMBOL(m, s, fnHook)									\
CMisc::OnDetourAttach(std::bind(CMisc::GetFunctionsVaFromSymbols, m, s, nullptr), fnHook);

// ͨ�������������ؽӿ�
// m ģ������
// s ��������
// fnHook ���Ӻ���
#define DETOUR_ATTACH_EXPORT(m, s, fnHook)									\
CMisc::OnDetourAttach(std::bind(CMisc::GetExportFunctionsVa, m, s), fnHook);