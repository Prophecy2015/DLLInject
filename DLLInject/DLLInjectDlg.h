
// DLLInjectDlg.h : 头文件
//

#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include <thread>
#include <mutex>
#include <set>

// CDLLInjectDlg 对话框
class CDLLInjectDlg : public CDialogEx
{
// 构造
public:
	CDLLInjectDlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLLINJECT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnBnClickedBtnSelPid();
	afx_msg void OnBnClickedBtnSelDll();
	afx_msg void OnBnClickedBtnInject();
	afx_msg void OnClose();
	afx_msg void OnMenuFileQuit();
	afx_msg void OnMenuDebugSetting();
	afx_msg void OnTcnSelchangeTabInfo(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg LRESULT OnReadMemoryData(WPARAM wParam, LPARAM lParam);
	afx_msg void OnSize(UINT nType, int cx, int cy);
	afx_msg void OnGetMinMaxInfo(MINMAXINFO* lpMMI);
	afx_msg void OnUpdateMenuDebugSetting(CCmdUI *pCmdUI);
	afx_msg void OnBnClickedCheckNotify();
	DECLARE_MESSAGE_MAP()
public:
	BOOL InjectedDLL();
	BOOL PulledOutDLL();
	void InsertInformation(TCHAR* szInfo, ...);
	CString GetFileName(CString strPathName);
	CString GetFileNameWithoutExt(CString strPathName);
	std::set<DWORD> GetPIDFromName(CString strExeName);
	int CopyDebugIniFile(DWORD dwPID);
	BOOL StartReadFromChannel(LPCTSTR szName);
	BOOL StopReadFromChannel();
	BOOL LoadConfig();
	BOOL SaveConfig();
	void ChangeTabItem(int iItem);
	CString FromUtf8(const char* szUtf8);
private:
	CString m_strProcName;
	DWORD m_dwSelPID;
	CString m_strDLLName;
	CString m_strDstIniPath;
	BOOL m_bInjected;
	CListCtrl m_ctrlInfo;
	CMenu m_ctrlMenu;
	CRichEditCtrl m_ctrlRichEdit;
	CTabCtrl m_ctrlTab;
	std::thread m_threadRead;
	BOOL	m_bStopThread;
	CString m_strLogInfo;
	CONFIG_INFO m_stuConfig;
	BOOL m_bPrintData;
	CButton m_btnPrint;
};
