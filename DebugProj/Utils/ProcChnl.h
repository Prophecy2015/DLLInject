#pragma once

#include "windows.h"
#include "tchar.h"

struct SHARED_HEAD
{
	DWORD iTotalSize;
	DWORD iUsedSize;
	BYTE byReserved[24];
};

struct SHARED_MEM 
{
	int    iValidFlag;	// 0-invalid, 1-valid
	HANDLE hMap;
	PBYTE  pByte;
	HANDLE hDataMutex;
	HANDLE hStopMutex;
};

#define SHARED_DATA_PTR(c) (c.pByte + sizeof(SHARED_HEAD))
#define SHARED_DATA_LEN(c) (((SHARED_HEAD*)c.pByte)->iUsedSize)
#define VALID_CHANNEL(c) (c.iValidFlag == 1)

typedef SHARED_MEM HCHANNEL;

namespace ProcChnl {
	HCHANNEL CreateChannel(LPCTSTR szName, int iSize);

	void CloseChannel(HCHANNEL& c);

	int GRead(HCHANNEL c, unsigned char* szBuf, int iMaxSize, int iMilliTimeout = INFINITE);

	int GWrite(HCHANNEL c, unsigned char* szBuf, int iSize, int iMilliTimeout = INFINITE);

	BOOL CanRead(HCHANNEL c);

	BOOL CanWrite(HCHANNEL c, DWORD dwWaitWriteSize);
}