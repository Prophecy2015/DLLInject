#include "ProcChnl.h"
#include "stdlib.h"
#include "stdio.h"
#include "sddl.h"

#define CHANNEL_BOUNDARY _T("ChannelBoundary")
#define CHANNEL_NAMESPACE _T("ChannelNameSpace")
#define SDDL_STRING _T("D:(A;;GA;;;WD)")

class CGlobal
{
private:
	CGlobal() : m_hBoundary(NULL), m_hNamespace(NULL) {
		Init();
	}

	~CGlobal()
	{
		Uninit();
	}
public:
	BOOL Init() { return CreateNameSpace(); }
	BOOL Uninit() { return DestoryNameSpace(); }
	BOOL CreateNameSpace();
	BOOL DestoryNameSpace();

	static CGlobal* GetInstance() {
		static CGlobal s_global;
		return &s_global;
	}
private:
	HANDLE m_hBoundary;
	HANDLE m_hNamespace;
};

BOOL CGlobal::CreateNameSpace() {

	// Create the boundary descriptor
	m_hBoundary = CreateBoundaryDescriptor(CHANNEL_BOUNDARY,0);

	BOOL bRet = FALSE;

	// resources that need cleanup
	HANDLE hToken = NULL;
	DWORD dwTokenInfoSize =0;
	PTOKEN_USER pTokenUser = NULL;
	LPVOID pSD = NULL;

	do
	{
		DWORD dwError =0;
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			dwError = GetLastError();
			printf("OpenProcessToken失败! 错误: %d\n", dwError);
			break;
		}

		GetTokenInformation(hToken, TokenUser, NULL,0, &dwTokenInfoSize);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			dwError = GetLastError();
			printf("GetTokenInformation(获取大小)失败! 错误: %d\n", dwError);
			break;
		}

		pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenInfoSize);
		if (!pTokenUser ||
			!GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize)) {
			dwError = GetLastError();
			printf("获取TokenUser信息失败! 错误: %d\n", dwError);
			break;
		}

		if (!AddSIDToBoundaryDescriptor(&m_hBoundary, pTokenUser->User.Sid)) {
			dwError = GetLastError();
			printf("AddSIDToBoundaryDescriptor失败! 错误: %d\n", dwError);
			break;
		}

		// Create the namespace for Local Administrators only
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = FALSE;
		sa.lpSecurityDescriptor = NULL;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
			SDDL_STRING,
			SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
		{
			dwError = GetLastError();
			printf("ConvertStringSecurityDescriptorToSecurityDescriptor失败! 错误: %d\n", dwError);
			break;
		}

		pSD = sa.lpSecurityDescriptor; // remember to free later

		m_hNamespace = CreatePrivateNamespace(&sa, m_hBoundary, CHANNEL_NAMESPACE);

		// Don't forget to release memory for the security descriptor
		if (pSD)
		{
			LocalFree(pSD);
			pSD = NULL;
		}

		// Check the private namespace creation result
		if (m_hNamespace == NULL) {
			// Nothing to do if access is denied
			// --> this code must run under a Local Administrator account
			DWORD dwLastError = GetLastError();
			if (dwLastError == ERROR_ACCESS_DENIED) {
				break;
			}
			else if (dwLastError == ERROR_ALREADY_EXISTS)
			{
				// If another instance has already created the namespace, 
				// we need to open it instead. 
				m_hNamespace = OpenPrivateNamespace(m_hBoundary, CHANNEL_NAMESPACE);
				if (m_hNamespace == NULL) {
					break;
				}
			}
			else {
				break;
			}
		}

		bRet = TRUE;
	} while (FALSE);

	// cleanup temporary resources
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}

	if (pTokenUser)
	{
		HeapFree(GetProcessHeap(),0, pTokenUser);
		pTokenUser = NULL;
	}

	if (FALSE == bRet)
	{
		if (m_hBoundary)
		{
			DeleteBoundaryDescriptor(m_hBoundary);
			m_hBoundary = NULL;
		}
	}

	return bRet;
}

BOOL CGlobal::DestoryNameSpace()
{
	if (NULL != m_hNamespace)
	{
		ClosePrivateNamespace(m_hNamespace,0);
		m_hNamespace = NULL;
	}

	if (NULL != m_hBoundary)
	{
		DeleteBoundaryDescriptor(m_hBoundary);
		m_hBoundary = NULL;
	}

	return TRUE;
}

namespace ProcChnl {
	HCHANNEL CreateChannel(LPCTSTR szName, int iSize)
	{
		CGlobal::GetInstance();

		HCHANNEL cnl = { 0 };

		bool bCreate = false;
		TCHAR szFullName[256] = {0};
		_sntprintf_s(szFullName, _countof(szFullName), _T("%s\\%s_MEMORY"), CHANNEL_NAMESPACE, szName);

		HANDLE hMap = ::OpenFileMapping(FILE_MAP_ALL_ACCESS, FALSE, szFullName);
		if (NULL == hMap)
		{
			hMap = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE,0, iSize + sizeof(SHARED_HEAD), szFullName);
			if (NULL == hMap)
			{
				return cnl;
			}

			bCreate = true;
		}
		cnl.hMap = hMap;
		do {

			LPVOID pByte = ::MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
			if (NULL == pByte)
			{
				break;
			}
			cnl.pByte = (PBYTE)pByte;

			// If opened existing mapping, validate size
			if (!bCreate)
			{
				SHARED_HEAD* pHead = (SHARED_HEAD*)pByte;
				if (pHead->iTotalSize < (DWORD)iSize)
				{
					break;
				}
			}

			if (bCreate)
			{
				// initialize header only
				memset(pByte, 0, sizeof(SHARED_HEAD));
			}

			TCHAR szDahuaName[256] = { 0 };
			_sntprintf_s(szDahuaName, _countof(szDahuaName), _T("%s\\%s_MUTEX"), CHANNEL_NAMESPACE, szName);
			cnl.hDataMutex = OpenMutex(MUTEX_ALL_ACCESS, FALSE, szDahuaName);
			if (NULL == cnl.hDataMutex)
			{
				// 创建新的，使用宽松的安全设置
				SECURITY_ATTRIBUTES sa = { 0 };
				// Create the namespace for Local Administrators only
				sa.nLength = sizeof(sa);
				sa.bInheritHandle = FALSE;
				// 创建新的，使用宽松的安全设置
				if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
					SDDL_STRING,
					SDDL_REVISION_1,
					&sa.lpSecurityDescriptor,
					NULL))
				{
					DWORD dwErr = GetLastError();
					printf("ConvertStringSecurityDescriptorToSecurityDescriptor失败! 错误: %d\n", dwErr);
					break;
				}
				if (!IsValidSecurityDescriptor(sa.lpSecurityDescriptor)) {
					break;
				}

				cnl.hDataMutex = CreateMutex(&sa, FALSE, szDahuaName);

				if (IsValidSecurityDescriptor(sa.lpSecurityDescriptor)) {
					LocalFree(sa.lpSecurityDescriptor);
				}

				if (NULL == cnl.hDataMutex) {
					DWORD dwErr = GetLastError();
					printf("CreateMutex failed! error:%d", dwErr);
					break;
				}
			}

			// create local stop event (unnamed)
			cnl.hStopEvent = ::CreateEvent(NULL, TRUE, FALSE, NULL);
			if (NULL == cnl.hStopEvent)
			{
				DWORD dwErr = GetLastError();
				printf("CreateEvent failed! error:%d", dwErr);
				break;
			}

			((SHARED_HEAD*)pByte)->iTotalSize = iSize;
			cnl.iValidFlag = 1;
			return cnl;
		} while (false);

		if (cnl.hStopEvent)
		{
			CloseHandle(cnl.hStopEvent);
			cnl.hStopEvent = NULL;
		}

		if (cnl.hDataMutex)
		{
			CloseHandle(cnl.hDataMutex);
			cnl.hDataMutex = NULL;
		}

		if (cnl.pByte)
		{
			UnmapViewOfFile(cnl.pByte);
			cnl.pByte = NULL;
		}

		if (cnl.hMap) {
			CloseHandle(cnl.hMap);
			cnl.hMap = NULL;
		}

		return cnl;
	}

	void CloseChannel(HCHANNEL& c)
	{
		if (c.iValidFlag ==1)
		{
			// Signal stop so waiting threads wake up and exit
			if (c.hStopEvent)
			{
				SetEvent(c.hStopEvent);
				CloseHandle(c.hStopEvent);
				c.hStopEvent = NULL;
			}

			if (c.hDataMutex)
			{
				CloseHandle(c.hDataMutex);
				c.hDataMutex = NULL;
			}

			if (c.pByte)
			{
				UnmapViewOfFile(c.pByte);
				c.pByte = NULL;
			}

			if (c.hMap)
			{
				CloseHandle(c.hMap);
				c.hMap = NULL;
			}

			c.iValidFlag =0;
		}
	}

	int GRead(HCHANNEL c, unsigned char* szBuf, int iMaxSize, int iMilliTimeout)
	{
		if (!c.iValidFlag)
		{
			return -1;
		}

		int iRet =0;
		HANDLE h[2] = { c.hDataMutex, c.hStopEvent };
		DWORD dwRet = WaitForMultipleObjectsEx(2, h, FALSE, iMilliTimeout, FALSE);
		switch (dwRet)
		{
		case WAIT_TIMEOUT:
		{
			iRet =0;
		}break;
		case WAIT_OBJECT_0:
		{
			SHARED_HEAD* pHead = (SHARED_HEAD*)c.pByte;
			if (pHead->iTotalSize >0 &&
				pHead->iUsedSize >0)
			{
				iRet = __min(SHARED_DATA_LEN(c), iMaxSize);
				memcpy(szBuf, SHARED_DATA_PTR(c), iRet);
				pHead->iUsedSize -= iRet;
				if (pHead->iUsedSize >0)
					memmove(SHARED_DATA_PTR(c), SHARED_DATA_PTR(c) + iRet, pHead->iUsedSize);
			}

			ReleaseMutex(c.hDataMutex);
		}break;
		case WAIT_OBJECT_0 +1:
		{
			iRet = -1; // stop signaled
		}break;
		default:
			break;
		}

		return iRet;
	}

	int GWrite(HCHANNEL c, unsigned char* szBuf, int iSize, int iMilliTimeout)
	{
		if (!c.iValidFlag)
		{
			return -1;
		}

		int iRet =0;
		HANDLE h[2] = { c.hDataMutex, c.hStopEvent };
		DWORD dwRet = WaitForMultipleObjectsEx(2, h, FALSE, iMilliTimeout, FALSE);
		switch (dwRet)
		{
		case WAIT_TIMEOUT:
		{
			iRet =0;
		}break;
		case WAIT_OBJECT_0:
		{
			// we now own the data mutex
			if (FALSE == CanWrite(c, iSize))
			{
				iRet = -1;
				ReleaseMutex(c.hDataMutex);
				break;
			}
			SHARED_HEAD* pHead = (SHARED_HEAD*)c.pByte;
			memcpy(SHARED_DATA_PTR(c) + pHead->iUsedSize, szBuf, iSize);
			pHead->iUsedSize += iSize;
			ReleaseMutex(c.hDataMutex);
		}break;
		case WAIT_OBJECT_0 +1:
		{
			iRet = -1;
		}break;
		default:
			break;
		}

		return iRet;
	}

	BOOL CanRead(HCHANNEL c)
	{
		if (!c.iValidFlag)
		{
			return FALSE;
		}

		DWORD dwTotalSize = *(DWORD*)c.pByte;
		DWORD dwCurSize = *(DWORD*)(c.pByte + sizeof(DWORD));

		return dwTotalSize >0 && dwCurSize >0;
	}

	BOOL CanWrite(HCHANNEL c, DWORD dwWaitWriteSize)
	{
		if (!c.iValidFlag)
		{
			return FALSE;
		}

		DWORD dwTotalSize = *(DWORD*)c.pByte;
		DWORD dwCurSize = *(DWORD*)(c.pByte + sizeof(DWORD));

		return (dwCurSize + dwWaitWriteSize) <= dwTotalSize;
	}
}
