#pragma once
#include "afxcmn.h"


// CPIDListDlg 对话框

class CPIDListDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CPIDListDlg)

public:
	CPIDListDlg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CPIDListDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_PID };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持
	virtual BOOL OnInitDialog();

	afx_msg void OnBnClickedBtnFrush();
	afx_msg void OnNMDblclkListPid(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnEnChangeEditSearch();
	afx_msg void OnBnClickedCheckAa();
	afx_msg void OnBnClickedCheckAbc();
	DECLARE_MESSAGE_MAP()
public:
	void UpdatePIDList();
	CString GetSelExeName() { return m_strProcName; }
	DWORD GetSelPID() { return m_dwSelPID; }
private:
	CListCtrl m_ctrlList;
	CString m_strProcName;
	DWORD m_dwSelPID;
	CString m_strSearch;
	BOOL m_bCheckAa;
	BOOL m_bCheckABC;
};
