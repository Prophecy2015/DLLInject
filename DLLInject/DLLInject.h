
// DLLInject.h : PROJECT_NAME Ӧ�ó������ͷ�ļ�
//

#pragma once

#ifndef __AFXWIN_H__
	#error "�ڰ������ļ�֮ǰ������stdafx.h�������� PCH �ļ�"
#endif

#include "resource.h"		// ������

#define DEBUG_SETTING_PATH _T(".\\GDebugInfo.ini")
// CDLLInjectApp: 
// �йش����ʵ�֣������ DLLInject.cpp
//

class CDLLInjectApp : public CWinApp
{
public:
	CDLLInjectApp();

// ��д
public:
	virtual BOOL InitInstance();

// ʵ��

	DECLARE_MESSAGE_MAP()
};

extern CDLLInjectApp theApp;
