
// DLLInjectDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "DLLInject.h"
#include "DLLInjectDlg.h"
#include "afxdialogex.h"
#include "PIDListDlg.h"
#include "DebugSetDlg.h"
#include "TLhelp32.h"
#include "ProcChnl.h"
#include <chrono>

#ifdef _DEBUG
#define new DEBUG_NEW
#endif

#define WM_READ_MEM WM_USER + 100
#define MAX_CHANNEL_BUFF_SIZE 32 * 1024 * 1024
// 用于应用程序“关于”菜单项的 CAboutDlg 对话框

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

// 实现
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CDLLInjectDlg 对话框



CDLLInjectDlg::CDLLInjectDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DLLINJECT_DIALOG, pParent)
	, m_strProcName(_T(""))
	, m_strDLLName(_T(""))
	, m_strDstIniPath(_T(""))
	, m_bInjected(FALSE)
	, m_bStopThread(FALSE)
	, m_strLogInfo(_T(""))
	, m_bPrintData(TRUE)
	, m_dwSelPID(0)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CDLLInjectDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_NAME, m_strProcName);
	DDX_Text(pDX, IDC_EDIT_DLL, m_strDLLName);
	DDX_Control(pDX, IDC_LIST_INFO, m_ctrlInfo);
	DDX_Control(pDX, IDC_RICHEDIT_INFO, m_ctrlRichEdit);
	DDX_Control(pDX, IDC_TAB_INFO, m_ctrlTab);
	DDX_Text(pDX, IDC_RICHEDIT_INFO, m_strLogInfo);
	DDX_Check(pDX, IDC_CHECK_NOTIFY, m_bPrintData);
	DDX_Control(pDX, IDC_CHECK_NOTIFY, m_btnPrint);
}

BEGIN_MESSAGE_MAP(CDLLInjectDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BTN_SEL_PID, &CDLLInjectDlg::OnBnClickedBtnSelPid)
	ON_BN_CLICKED(IDC_BTN_SEL_DLL, &CDLLInjectDlg::OnBnClickedBtnSelDll)
	ON_BN_CLICKED(IDC_BTN_INJECT, &CDLLInjectDlg::OnBnClickedBtnInject)
	ON_WM_CLOSE()
	ON_COMMAND(ID_MENU_FILE_QUIT, &CDLLInjectDlg::OnMenuFileQuit)
	ON_COMMAND(ID_MENU_DEBUG_SETTING, &CDLLInjectDlg::OnMenuDebugSetting)
	ON_NOTIFY(TCN_SELCHANGE, IDC_TAB_INFO, &CDLLInjectDlg::OnTcnSelchangeTabInfo)
	ON_MESSAGE(WM_READ_MEM, &CDLLInjectDlg::OnReadMemoryData)
	ON_WM_SIZE()
	ON_WM_GETMINMAXINFO()
	ON_UPDATE_COMMAND_UI(ID_MENU_DEBUG_SETTING, &CDLLInjectDlg::OnUpdateMenuDebugSetting)
	ON_BN_CLICKED(IDC_CHECK_NOTIFY, &CDLLInjectDlg::OnBnClickedCheckNotify)
END_MESSAGE_MAP()


// CDLLInjectDlg 消息处理程序

BOOL CDLLInjectDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 将“关于...”菜单项添加到系统菜单中。

	// IDM_ABOUTBOX 必须在系统命令范围内。
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	// TODO: 在此添加额外的初始化代码
	LoadConfig();
	m_ctrlMenu.LoadMenu(IDR_MENU_MAIN);
	SetMenu(&m_ctrlMenu);

	ListView_SetExtendedListViewStyle(m_ctrlInfo.GetSafeHwnd(),
		ListView_GetExtendedListViewStyle(m_ctrlInfo.GetSafeHwnd()) | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);
	m_ctrlInfo.InsertColumn(0, _T("Info"), LVCFMT_CENTER, 1000);

	m_ctrlTab.InsertItem(0, _T("操作信息"));
	m_ctrlTab.InsertItem(1, _T("调试信息"));

	m_ctrlTab.SetCurSel(0);
	ChangeTabItem(0);

	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}

void CDLLInjectDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。

void CDLLInjectDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR CDLLInjectDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CDLLInjectDlg::OnBnClickedBtnSelPid()
{
	// TODO: 在此添加控件通知处理程序代码
	CPIDListDlg dlg;
	if (IDOK == dlg.DoModal())
	{
		m_strProcName.Format(_T("%s"), dlg.GetSelExeName().GetBuffer());
		m_dwSelPID = dlg.GetSelPID();
		UpdateData(FALSE);
	}
}


void CDLLInjectDlg::OnBnClickedBtnSelDll()
{
	// TODO: 在此添加控件通知处理程序代码
	CFileDialog file(true, _T("*.dll"), _T(""), 0, _T("DLL|*.dll||"), this);
	if (IDOK == file.DoModal())
	{
		m_strDLLName = file.GetPathName();
		UpdateData(FALSE);
	}
}

BOOL CDLLInjectDlg::InjectedDLL()
{
	UpdateData(TRUE);
	if (m_strProcName.IsEmpty())
	{
		InsertInformation(_T("请选择需要调试的进程！"));
		return FALSE;
	}

	if (m_strDLLName.IsEmpty())
	{
		InsertInformation(_T("请选择需要注入的调试DLL！"));
		return FALSE;
	}

	std::set<DWORD> setPIDs = GetPIDFromName(m_strProcName);
	if (setPIDs.empty())
	{
		InsertInformation(_T("找不到%s进程.\n"), m_strProcName);
		return FALSE;
	}

	if (setPIDs.end() == setPIDs.find(m_dwSelPID))
	{
		m_dwSelPID = *setPIDs.begin();
	}

	CopyDebugIniFile(m_dwSelPID);

	// Get process handle passing in the process ID
	HANDLE hProcess = OpenProcess(
		PROCESS_QUERY_INFORMATION |
		PROCESS_CREATE_THREAD |
		PROCESS_VM_OPERATION |
		PROCESS_VM_WRITE,
		FALSE, m_dwSelPID);
	if (hProcess == NULL)
	{
		InsertInformation(_T("无法打开PID为%d的进程.\n"), m_dwSelPID);
		return FALSE;
	}

#ifdef _UNICODE
	const char* szFunc = "LoadLibraryW";
#else
	const char* szFunc = "LoadLibraryA";
#endif

	// Get the real address of LoadLibraryW in Kernel32.dll

	HMODULE hModule = GetModuleHandle(_T("Kernel32.dll"));
	if (0 == hModule)
	{
		InsertInformation(_T("进程(%d)中找不到模块Kernel32.dll!!! [%d]\n"), m_dwSelPID, GetLastError());
		return FALSE;
	}

	PTHREAD_START_ROUTINE pfnThreadRtn = (PTHREAD_START_ROUTINE)GetProcAddress(hModule, szFunc);
	if (pfnThreadRtn == NULL)
	{
		InsertInformation(_T("无法在kernel32.dll找到%s 函数！\n"), szFunc);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Calculate the number of bytes needed for the DLL's pathname
	size_t dwSize = m_strDLLName.GetLength() * sizeof(TCHAR);
	// Allocate space in the remote process for the pathname
	LPVOID pszLibFileRemote = (PWSTR)VirtualAllocEx(hProcess, NULL, dwSize + 1, MEM_COMMIT, PAGE_READWRITE);
	if (pszLibFileRemote == NULL)
	{
		InsertInformation(_T("Could not allocate memory inside PID  (%d).\n"), m_dwSelPID);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Copy the DLL's pathname to the remote process address space
	DWORD n = WriteProcessMemory(hProcess, pszLibFileRemote, (PVOID)m_strDLLName.GetBuffer(), dwSize, NULL);
	if (n == 0)
	{
		InsertInformation(_T("无法向 PID [%d] 地址空间[%p]写入数据！\n"), m_dwSelPID, pszLibFileRemote);
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}

	// Create a remote thread that calls LoadLibraryW(DLLPathname)
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, pfnThreadRtn, pszLibFileRemote, 0, NULL);
	if (hThread == NULL)
	{
		InsertInformation(_T("创建远程线程失败！\n"));
		VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);

	CloseHandle(hThread);
	VirtualFreeEx(hProcess, pszLibFileRemote, 0, MEM_RELEASE);
	CloseHandle(hProcess);

	if (m_stuConfig.iPrintMode == 0 )
	{
		StartReadFromChannel(GetFileNameWithoutExt(m_strDLLName));
		m_strLogInfo = _T("");
	}
	else
	{
		m_strLogInfo = _T("当前选择打印到控制台");
	}
	UpdateData(FALSE);

	InsertInformation(_T("[%u]:调试库[%s]注入完成！"), m_dwSelPID, GetFileName(m_strDLLName));
	return TRUE;
}

BOOL CDLLInjectDlg::PulledOutDLL()
{
	if (m_stuConfig.iPrintMode == 0)
	{
		StopReadFromChannel();
	}

	//DWORD dwPID = GetPIDFromName(m_strProcName);
	//if (dwPID == 0)
	//{
	//	InsertInformation(_T("无法打开%s进程.\n"), m_strProcName);
	//	return FALSE;
	//}

	if (m_dwSelPID == 0)
	{
		InsertInformation(_T("请选择需要卸载模块的进程！"));
		return FALSE;
	}

	HANDLE hSnapshot, hProcess, hThread;
	HMODULE hModule;
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE, bFind = FALSE;
	LPTHREAD_START_ROUTINE pThreadProc;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, m_dwSelPID);
	if (hSnapshot == NULL)
	{
		InsertInformation(_T("[PID:%d] GetModuleSnap Failed!.\n"), m_dwSelPID);
		return FALSE;
	}
	bMore = Module32First(hSnapshot, &me);
	for (; bMore; bMore = Module32Next(hSnapshot, &me))
	{
		if (m_strDLLName == me.szExePath)
		{
			bFind = TRUE;
			break;
		}
	}

	if (bFind == FALSE)
	{
		InsertInformation(_T("进程中找不到指定模块"));
		CloseHandle(hSnapshot);
		return FALSE;
	}

	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, m_dwSelPID);
	if (!hProcess)
	{
		InsertInformation(_T("打开进程(%d) 失败!!! [%d]\n"), m_dwSelPID, GetLastError());
		CloseHandle(hSnapshot);
		return FALSE;
	}
	hModule = GetModuleHandle(_T("Kernel32.dll"));
	if (0 == hModule)
	{
		InsertInformation(_T("进程(%d)中找不到模块Kernel32.dll!!! [%d]\n"), m_dwSelPID, GetLastError());
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hModule, "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0, pThreadProc, me.modBaseAddr, 0, NULL);
	if (hThread == NULL)
	{
		InsertInformation(_T("创建远程线程失败！\n"));
		CloseHandle(hProcess);
		CloseHandle(hSnapshot);
		return FALSE;
	}
	WaitForSingleObject(hThread, INFINITE);

	DWORD dwExitCode = 0;
	GetExitCodeThread(hThread, &dwExitCode);
	if (dwExitCode == 1)
	{
		InsertInformation(_T("[%u]:调试库[%s]卸载完成！"), m_dwSelPID, GetFileName(m_strDLLName));
	}
	else
	{
		InsertInformation(_T("FreeLibrary调用失败！"));
	}

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	if (!m_strDstIniPath.IsEmpty())
	{
		DeleteFile(m_strDstIniPath);
		m_strDstIniPath = _T("");
	}
	return TRUE;
}

void CDLLInjectDlg::InsertInformation(TCHAR* szInfo, ...)
{
	TCHAR szTmp[2048] = { 0 };
	va_list vl;
	va_start(vl, szInfo);
	_vstprintf_s(szTmp, szInfo, vl);
	va_end(vl);
	((CListCtrl*)GetDlgItem(IDC_LIST_INFO))->InsertItem(0, szTmp);
}

CString CDLLInjectDlg::GetFileName(CString strPathName)
{
	int iPos = strPathName.ReverseFind(_T('\\'));
	if (-1 == iPos)
	{
		return strPathName;
	}

	return strPathName.Right(strPathName.GetLength() - iPos - 1);
}

CString CDLLInjectDlg::GetFileNameWithoutExt(CString strPathName)
{
	int iPos = strPathName.ReverseFind(_T('\\'));
	int iPos1 = strPathName.ReverseFind(_T('.'));
	if (-1 == iPos && -1 == iPos1)
	{
		return strPathName;
	}
	else if (-1 == iPos)
	{
		return strPathName.Left(iPos1);
	}
	else if (-1 == iPos1)
	{
		return strPathName.Right(strPathName.GetLength() - iPos - 1);
	}
	else if (iPos1 - iPos - 1 > 0)
	{
		return strPathName.Mid(iPos + 1, iPos1 - iPos - 1);
	}

	return strPathName;
}

void CDLLInjectDlg::OnBnClickedBtnInject()
{
	// TODO: 在此添加控件通知处理程序代码
	if (FALSE == m_bInjected)
	{
		if (TRUE == InjectedDLL())
		{
			m_bInjected = TRUE;

			if (m_stuConfig.iPrintMode == 0)
			{
				m_ctrlTab.SetCurSel(1);
				ChangeTabItem(1);
			}
		}
	}
	else
	{
		PulledOutDLL();
		m_bInjected = FALSE;
	}
	GetDlgItem(IDC_BTN_INJECT)->SetWindowText(m_bInjected ? _T("卸载") : _T("注入"));
	GetDlgItem(IDC_BTN_SEL_PID)->EnableWindow(!m_bInjected);
	GetDlgItem(IDC_BTN_SEL_DLL)->EnableWindow(!m_bInjected);
}


std::set<DWORD> CDLLInjectDlg::GetPIDFromName(CString strExeName)
{
	std::set<DWORD> setPIDs;
	// 获取全部快照
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		AfxMessageBox(_T("获取进程快照失败！"));
		return setPIDs;
	}

	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	BOOL bRet = ::Process32First(hProcessSnap, &pe32);

	while (bRet)
	{
		if (strExeName == pe32.szExeFile)
		{
			setPIDs.insert(pe32.th32ProcessID);
		}

		bRet = ::Process32Next(hProcessSnap, &pe32);
	}

	return setPIDs;
}


void CDLLInjectDlg::OnClose()
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值

	if (TRUE == m_bInjected)
	{
		if (IDCANCEL == AfxMessageBox(_T("正在调试，是否确认退出？"), MB_OKCANCEL))
		{
			return;
		}
		PulledOutDLL();
		m_bInjected = FALSE;

		GetDlgItem(IDC_BTN_INJECT)->SetWindowText(m_bInjected ? _T("卸载") : _T("注入"));
		GetDlgItem(IDC_BTN_SEL_PID)->EnableWindow(!m_bInjected);
		GetDlgItem(IDC_BTN_SEL_DLL)->EnableWindow(!m_bInjected);
	}

	CDialogEx::OnClose();
}


void CDLLInjectDlg::OnMenuFileQuit()
{
	// TODO: 在此添加命令处理程序代码
	SendMessage(WM_CLOSE);
}


void CDLLInjectDlg::OnMenuDebugSetting()
{
	// TODO: 在此添加命令处理程序代码
	CDebugSetDlg dlg(m_stuConfig);
	if (IDOK == dlg.DoModal())
	{
		//.TODO
		m_stuConfig = dlg.GetConfigParam();
		SaveConfig();
	}
}


int CDLLInjectDlg::CopyDebugIniFile(DWORD dwPID)
{
	HANDLE hSnapshot;
	MODULEENTRY32 me = { sizeof(me) };
	BOOL bMore = FALSE, bFind = FALSE;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID);
	if (hSnapshot == NULL)
	{
		InsertInformation(_T("[PID:%d] GetModuleSnap Failed!.\n"), dwPID);
		return FALSE;
	}
	bMore = Module32First(hSnapshot, &me);

	CString strExePath = me.szExePath;
	m_strDstIniPath = strExePath.Left(strExePath.ReverseFind(_T('\\')) + 1) + _T("GDebugInfo.ini");

	CopyFile(DEBUG_SETTING_PATH, m_strDstIniPath, FALSE);

	return 0;
}

BOOL CDLLInjectDlg::StartReadFromChannel(LPCTSTR szName)
{
	m_bStopThread = FALSE;
	CString strName = szName;
	m_threadRead = std::thread(
		[this, strName]() {

		HCHANNEL s = ProcChnl::CreateChannel(strName, MAX_CHANNEL_BUFF_SIZE);
		if (VALID_CHANNEL(s))
		{
			unsigned char* szTmp = new unsigned char[4096];
			memset(szTmp, 0, sizeof(szTmp));
			while (!m_bStopThread)
			{
				if (m_bPrintData && ProcChnl::CanRead(s))
				{
					int iRead = ProcChnl::GRead(s, szTmp, 4096);
					if (iRead > 0)
					{
						unsigned char* szMsg = new unsigned char[iRead];
						memcpy(szMsg, szTmp, iRead);
						this->PostMessage(WM_READ_MEM, (WPARAM)szMsg, (LPARAM)iRead);
					}
				}

				std::this_thread::sleep_for(std::chrono::milliseconds(20));
			}

			delete [] szTmp;
			ProcChnl::CloseChannel(s);
		}

		}
	);

	return TRUE;
}

BOOL CDLLInjectDlg::StopReadFromChannel()
{
	if (m_threadRead.joinable())
	{
		m_bStopThread = TRUE;
		m_threadRead.join();
	}

	return TRUE;
}

BOOL CDLLInjectDlg::LoadConfig()
{
	TCHAR szTemp[256] = { 0 };
	GetPrivateProfileString(_T("Debug"), _T("PDB"), _T("."), szTemp, sizeof(szTemp) / sizeof(TCHAR), DEBUG_SETTING_PATH);
	m_stuConfig.strPDBPath = szTemp;

	m_stuConfig.iPrintMode = GetPrivateProfileInt(_T("Debug"), _T("Mode"), 0, DEBUG_SETTING_PATH);
	m_stuConfig.iCodePage = GetPrivateProfileInt(_T("Debug"), _T("Code"), 0, DEBUG_SETTING_PATH);

	return TRUE;
}

BOOL CDLLInjectDlg::SaveConfig()
{
	WritePrivateProfileString(_T("Debug"), _T("PDB"), m_stuConfig.strPDBPath.GetBuffer(), DEBUG_SETTING_PATH);
	m_stuConfig.strPDBPath.ReleaseBuffer();

	CString strTmp;
	strTmp.Format(_T("%d"), m_stuConfig.iPrintMode);
	WritePrivateProfileString(_T("Debug"), _T("Mode"), strTmp.GetBuffer(), DEBUG_SETTING_PATH);
	strTmp.ReleaseBuffer();

	strTmp.Format(_T("%d"), m_stuConfig.iCodePage);
	WritePrivateProfileString(_T("Debug"), _T("Code"), strTmp.GetBuffer(), DEBUG_SETTING_PATH);
	strTmp.ReleaseBuffer();
	return TRUE;
}

void CDLLInjectDlg::OnTcnSelchangeTabInfo(NMHDR *pNMHDR, LRESULT *pResult)
{
	// TODO: 在此添加控件通知处理程序代码
	int idx = m_ctrlTab.GetCurSel();
	ChangeTabItem(idx);
	*pResult = 0;
}

LRESULT CDLLInjectDlg::OnReadMemoryData(WPARAM wParam, LPARAM lParam)
{
	unsigned char* szMsg = (unsigned char*)wParam;
	int iSize = (int)lParam;
	if (szMsg)
	{
		m_strLogInfo += (m_stuConfig.iCodePage == 1) ? FromUtf8((char*)szMsg) : CString((LPCTSTR)szMsg, iSize / sizeof(TCHAR));
		UpdateData(FALSE);
		delete[]szMsg;
		m_ctrlRichEdit.PostMessage(WM_VSCROLL, SB_BOTTOM, 0);
	}
	return TRUE;
}


void CDLLInjectDlg::OnSize(UINT nType, int cx, int cy)
{
	CDialogEx::OnSize(nType, cx, cy);

	// TODO: 在此处添加消息处理程序代码
	//if (GetDlgItem(IDC_LIST_INFO) != NULL &&
	//	GetDlgItem(IDC_RICHEDIT_INFO) != NULL)
	//{
	//	GetDlgItem(IDC_LIST_INFO)->MoveWindow(rtInfo);
	//	GetDlgItem(IDC_RICHEDIT_INFO)->MoveWindow(rtInfo);
	//}
	if (nullptr != m_ctrlRichEdit.GetSafeHwnd())
	{
		CRect rtInfo(12, 103, cx - 10, cy - 10);
		m_ctrlInfo.MoveWindow(rtInfo);
		m_ctrlRichEdit.MoveWindow(rtInfo);
	}
}

void CDLLInjectDlg::OnGetMinMaxInfo(MINMAXINFO* lpMMI)
{
	// TODO: 在此添加消息处理程序代码和/或调用默认值
	//调整最小高度与宽度,如果需要的话
	lpMMI->ptMinTrackSize.x = 650;
	lpMMI->ptMinTrackSize.y = 550;
	//调整最大高度与宽度,如果需要的话
	lpMMI->ptMaxTrackSize.x = 1980;
	lpMMI->ptMaxTrackSize.y = 1080;

	CDialogEx::OnGetMinMaxInfo(lpMMI);
}


void CDLLInjectDlg::OnUpdateMenuDebugSetting(CCmdUI *pCmdUI)
{
	// TODO: 在此添加命令更新用户界面处理程序代码
	pCmdUI->Enable(m_bInjected == FALSE);
}


void CDLLInjectDlg::ChangeTabItem(int iItem)
{
	m_ctrlInfo.ShowWindow(iItem == 0 ? SW_SHOW : SW_HIDE);
	m_ctrlRichEdit.ShowWindow(iItem == 1 ? SW_SHOW : SW_HIDE);
	m_btnPrint.ShowWindow(iItem == 1 ? SW_SHOW : SW_HIDE);
}


void CDLLInjectDlg::OnBnClickedCheckNotify()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData();
}

CString CDLLInjectDlg::FromUtf8(const char* szUtf8)
{
	CString strRet;

	size_t WLength = MultiByteToWideChar(CP_UTF8, 0, szUtf8, -1, NULL, NULL);
	LPWSTR pszW = new wchar_t[WLength + 1];
	MultiByteToWideChar(CP_UTF8, 0, szUtf8, -1, pszW, WLength);
	pszW[WLength] = 0;

#ifndef UNICODE
	int MLength = WideCharToMultiByte(CP_ACP, 0, pszW, WLength, NULL, -1, NULL, NULL);
	LPSTR pszC = new char[MLength + 1];
	WideCharToMultiByte(CP_ACP, 0, pszW, WLength, pszC, MLength, NULL, NULL);
	strRet = pszC;
	delete[]pszC;
#else
	strRet = pszW;
#endif

	delete[]pszW;

	return strRet;
}

