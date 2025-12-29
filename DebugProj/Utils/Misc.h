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

#define CUSTOM_SYMBOL_PATH ".;D:\\32055\\pdb" //多个路径以分号分隔
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
	* \brief 通过加载pdb文件，以内部函数名称查找对于虚拟地址，需要pdb文件支持，否则会查找失败
	* \param szModuleName 模块名称
	* \param szFunctionName 需要查找的函数名称
	* \param szSymPath PDB文件查找路径，不填默认exe当前路径查找
	* \return 若查找成功，返回函数代码在当前进程虚拟地址，若查找失败，则返回NULL
	*/ 
	static PVOID GetFunctionsVaFromSymbols(PCTSTR szModuleName, PCTSTR szFunctionName, PCTSTR szSymPath = nullptr);

	/**
	* \brief 通过导出表，查找函数相对虚拟地址 RVA
	* \param hModule 模块句柄(其实就是模块在进程中加载的虚拟地址)
	* \param strFuncName 导出函数名称
	* \return 若查找成功，返回函数代码在当前进程相对虚拟地址，若查找失败，则返回0
	*/
	static DWORD GetExportFunctionsRva(HMODULE hModule, PCTSTR strFuncName);

	/**
	* \brief 通过导出表，查找函数虚拟地址 VA
	* \param szModuleName 模块名称
	* \param strFuncName 导出函数名称
	* \return 若查找成功，返回函数代码在当前进程虚拟地址，若查找失败，则返回NULL
	* \note 该函数针对导出符号，所以，即便没有pdb文件，只要名称在模块的导出表中，都可以查询出来，限制是，只能查找导出的接口，内部接口无法使用该函数
	*/
	static PVOID GetExportFunctionsVa(PCTSTR szModuleName, PCTSTR szFuncName);

	/**
	* \brief 在段内查找符合指定内存块内容的虚拟地址
	* \param pSection 段虚拟地址
	* \param dwSectionSize 段大小
	* \param pDataBase 待查找数据内存块
	* \param dwSize 数据内存块大小
	* \return 若查找成功，返回指定内存块在当前进程中的虚拟地址，若查找失败，则返回NULL
	* \note 该函数以二进制数据匹配虚拟地址，主要用于hook everywhere,hook任意位置使用，但是，很容易导致调试进程崩溃，慎用。
	*/
	static PVOID FindModuleMemoryFromSection(PBYTE pSection, DWORD dwSectionSize, PBYTE pDataBase, DWORD dwSize);

	/**
	* \brief 在指定模块中查找符合指定内存块内容的虚拟地址
	* \param hModule 待查找的模块句柄
	* \param pDataBase 待查找数据内存块
	* \param dwSize 数据内存块大小
	* \return 若查找成功，返回指定内存块在当前进程中的虚拟地址，若查找失败，则返回NULL
	* \note 该函数以二进制数据匹配虚拟地址，主要用于定位任意位置使用，但是，对位置地址的操作很容易导致调试进程崩溃，慎用.
	*/
	static PVOID FindModuleMemory(HMODULE hModule, PBYTE pDataBase, DWORD dwSize);

	/**
	* \brief 查找符合指定内存块内容的虚拟地址
	* \param pDataBase 待查找数据内存块
	* \param dwSize 数据内存块大小
	* \param szModuleName 可以指定模块名称
	* \return 若查找成功，返回指定内存块在当前进程中的虚拟地址，若查找失败，则返回NULL
	* \note 该函数以二进制数据匹配虚拟地址，主要用于定位任意位置使用，但是，对位置地址的操作很容易导致调试进程崩溃，慎用。
	*/
	static PVOID FindMemory(PBYTE pDataBase, DWORD dwSize, PCTSTR szModuleName = nullptr);

	/**
	* \brief 获取指定地址的符号名称，可能获取失败
	* \param address 地址
	* \param szSymPath 符号文件路径
	* \return 若查找成功，返回指定地址的符号名称，否则返回空
	*/
	static _tstring SymbolStrFromAddr(DWORD64 address, PCTSTR szSymPath = nullptr);

	/**
	* \brief 获取指定地址所在的模块名称
	* \param address 地址
	* \return 若查找成功，返回模块名称，否则返回空
	*/
	static _tstring AddrModuleName(DWORD64 address);

	/**
	* \brief 显示当前调用栈
	* \return void
	*/
	static void ShowTraceStarck();

	/**
	* \brief 显示指定上下文的堆栈
	* \return void
	*/
	static void ShowContextStackTrace(CONTEXT& cr);

	// Utils
	// 打印某个模块的所有符号
	static void PrintModuleSymbols(PCTSTR szModuleName, PCTSTR szSaveFile = nullptr);

	// 控制台初始化
	static BOOL InitConsole(HINSTANCE hIns);
	static BOOL UnInitConsole();
	// 共享内存初始化
	static BOOL InitSharedMemory(LPCTSTR szName);
	static BOOL UnInitSharedMemory();

	// HOOK
	static BOOL InitData();
	static BOOL BeginWork();
	static BOOL EndWork();
	static BOOL StartWork(HINSTANCE hIns);
	static BOOL StopWork();

	static PVOID GetOldAddr(PVOID fnHook);
	// Attach 钩子函数 
	static void OnDetourAttach(std::function<PVOID(void)> fn, PVOID fnHook);

	static void WriteLog(LPCTSTR szFmt, ...);

	static void WriteLogV(LPCTSTR szFmt, va_list _ArgList);

	static _tstring GetNowTimeStr();

	static std::string W2M(const std::wstring&);

	static std::wstring M2W(const std::string&);

	static _tstring GetFileName(_tstring strFilePathName);

	static _tstring GetFileNameWithOutExt(_tstring strFilePathName);

	static _tstring FormatHex(BYTE* buf, int len);

	static BOOL EnablePrivilegeDebug(BOOL bEnable);
};

// 通过PDB符号拦截接口
// m 模块名称
// s 符号名称
// fnHook 钩子函数
#define DETOUR_ATTACH_SYMBOL(m, s, fnHook)									\
CMisc::OnDetourAttach(std::bind(CMisc::GetFunctionsVaFromSymbols, m, s, nullptr), fnHook);

// 通过导出表导出拦截接口
// m 模块名称
// s 符号名称
// fnHook 钩子函数
#define DETOUR_ATTACH_EXPORT(m, s, fnHook)									\
CMisc::OnDetourAttach(std::bind(CMisc::GetExportFunctionsVa, m, s), fnHook);