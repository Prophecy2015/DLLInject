#include "ProcChnl.h"
#include "stdlib.h"
#include "stdio.h"
#include "sddl.h"

#define CHANNEL_BOUNDARY _T("ChannelBoundary")
#define CHANNEL_NAMESPACE _T("ChannelNameSpace")

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
	m_hBoundary = CreateBoundaryDescriptor(CHANNEL_BOUNDARY, 0);

	BOOL bRet = FALSE;
	do
	{
		// 2. === 关键步骤：获取当前用户SID并添加到边界 ===
		HANDLE hToken = NULL;
		DWORD dwTokenInfoSize = 0;
		PTOKEN_USER pTokenUser = NULL;
		// Check the private namespace creation result
		DWORD dwError = 0;

		// 2.1 打开当前进程的令牌
		if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
			dwError = GetLastError();
			printf("OpenProcessToken 失败! 错误: %d\n", dwError);
			break;
		}

		// 2.2 获取所需缓冲区大小
		GetTokenInformation(hToken, TokenUser, NULL, 0, &dwTokenInfoSize);
		if (GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
			dwError = GetLastError();
			printf("GetTokenInformation(获取大小) 失败! 错误: %d\n", dwError);
			break;
		}

		// 2.3 分配内存并获取用户SID信息
		pTokenUser = (PTOKEN_USER)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwTokenInfoSize);
		if (!pTokenUser ||
			!GetTokenInformation(hToken, TokenUser, pTokenUser, dwTokenInfoSize, &dwTokenInfoSize)) {
			dwError = GetLastError();
			printf("获取TokenUser信息失败! 错误: %d\n", dwError);
			break;
		}

		// Associate the Local Admin SID to the boundary descriptor
		// --> only applications running under an administrator user
		//     will be able to access the kernel objects in the same namespace
		if (!AddSIDToBoundaryDescriptor(&m_hBoundary, pTokenUser->User.Sid)) {
			break;
		}

		// Create the namespace for Local Administrators only
		SECURITY_ATTRIBUTES sa;
		sa.nLength = sizeof(sa);
		sa.bInheritHandle = FALSE;
		if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
			TEXT("D:(A;;GA;;;BA)"),
			SDDL_REVISION_1, &sa.lpSecurityDescriptor, NULL))
		{
			break;
		}

		m_hNamespace =
			CreatePrivateNamespace(NULL, m_hBoundary, CHANNEL_NAMESPACE);

		// Don't forget to release memory for the security descriptor
		LocalFree(sa.lpSecurityDescriptor);


		// Check the private namespace creation result
		DWORD dwLastError = GetLastError();
		if (m_hNamespace == NULL) {
			// Nothing to do if access is denied
			// --> this code must run under a Local Administrator account
			if (dwLastError == ERROR_ACCESS_DENIED) {
				break;
			}
			else  if (dwLastError == ERROR_ALREADY_EXISTS)
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
		ClosePrivateNamespace(m_hNamespace, 0);
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
		HANDLE hMap = ::OpenFileMapping(FILE_MAP_ALL_ACCESS, 0, szName);
		if (NULL == hMap)
		{
			hMap = ::CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, iSize + sizeof(SHARED_HEAD), szName);
			if (NULL == hMap)
			{
				return cnl;
			}

			bCreate = true;
		}

		LPVOID pByte = ::MapViewOfFile(hMap, FILE_MAP_ALL_ACCESS, 0, 0, 0);
		if (NULL == pByte)
		{
			CloseHandle(hMap);
			return cnl;
		}

		if (bCreate)
		{
			memset(pByte, 0, sizeof(SHARED_HEAD));
		}

		TCHAR szDahuaName[64] = { 0 };
		_sntprintf_s(szDahuaName, sizeof(szDahuaName) / sizeof(TCHAR), _T("%s\\%s"), CHANNEL_NAMESPACE, szName);
		cnl.hDataMutex = CreateMutex(NULL, FALSE, szDahuaName);
		if (NULL == cnl.hDataMutex)
		{
			DWORD dwErr = GetLastError();
			UnmapViewOfFile(pByte);
			CloseHandle(hMap);
			return cnl;
		}

		cnl.hStopMutex = ::CreateMutex(NULL, FALSE, NULL);
		cnl.hMap = hMap;
		cnl.pByte = (PBYTE)pByte;

		((SHARED_HEAD*)pByte)->iTotalSize = iSize;
		cnl.iValidFlag = 1;

		return cnl;
	}

	void CloseChannel(HCHANNEL& c)
	{
		if (c.iValidFlag == 1)
		{
			ReleaseMutex(c.hStopMutex);
			WaitForSingleObject(c.hStopMutex, INFINITE);
			ReleaseMutex(c.hStopMutex);
			CloseHandle(c.hStopMutex);

			ReleaseMutex(c.hDataMutex);
			CloseHandle(c.hDataMutex);

			UnmapViewOfFile(c.pByte);
			CloseHandle(c.hMap);

			c.iValidFlag = 0;
		}
	}

	int GRead(HCHANNEL c, unsigned char* szBuf, int iMaxSize, int iMilliTimeout)
	{
		if (!c.iValidFlag)
		{
			return -1;
		}

		int iRet = 0;
		HANDLE h[2] = { c.hDataMutex, c.hStopMutex };
		DWORD dwRet = WaitForMultipleObjectsEx(2, h, FALSE, iMilliTimeout, FALSE);
		switch (dwRet)
		{
		case WAIT_TIMEOUT:
		{
			iRet = 0;
		}break;
		case WAIT_OBJECT_0:
		{
			SHARED_HEAD* pHead = (SHARED_HEAD*)c.pByte;
			if (pHead->iTotalSize > 0 &&
				pHead->iUsedSize > 0)
			{
				iRet = __min(SHARED_DATA_LEN(c), iMaxSize);
				memcpy(szBuf, SHARED_DATA_PTR(c), iRet);
				pHead->iUsedSize -= iRet;
				if (pHead->iUsedSize > 0)
					memmove(SHARED_DATA_PTR(c), SHARED_DATA_PTR(c) + iRet, pHead->iUsedSize);
			}

			ReleaseMutex(c.hDataMutex);
		}break;
		case WAIT_OBJECT_0 + 1:
		{
			iRet = -1;
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

		int iRet = 0;
		HANDLE h[2] = { c.hDataMutex, c.hStopMutex };
		DWORD dwRet = WaitForMultipleObjectsEx(2, h, FALSE, iMilliTimeout, FALSE);
		switch (dwRet)
		{
		case WAIT_TIMEOUT:
		{
			iRet = 0;
		}break;
		case WAIT_OBJECT_0:
		{
			if (FALSE == CanWrite(c, iSize))
			{
				iRet = -1;
			}

			SHARED_HEAD* pHead = (SHARED_HEAD*)c.pByte;
			memcpy(SHARED_DATA_PTR(c) + pHead->iUsedSize, szBuf, iSize);
			pHead->iUsedSize += iSize;

			ReleaseMutex(c.hDataMutex);
		}break;
		case WAIT_OBJECT_0 + 1:
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

		return dwTotalSize > 0 && dwCurSize > 0;
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
