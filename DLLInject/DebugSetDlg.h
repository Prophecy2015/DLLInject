#pragma once
#include "afxwin.h"


// CDebugSetDlg 对话框

class CDebugSetDlg : public CDialogEx
{
	DECLARE_DYNAMIC(CDebugSetDlg)

public:
	CDebugSetDlg(CONFIG_INFO stuCfg, CWnd* pParent = NULL);   // 标准构造函数
	virtual ~CDebugSetDlg();

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DLG_PDB };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedBtnBrowse();
private:
	virtual BOOL OnInitDialog();
public:
	CONFIG_INFO GetConfigParam();
private:
	CString m_strPDBPath;
	BOOL m_bConsole;
	CONFIG_INFO m_stuCfg;
	CComboBox m_ctrlCodePage;
};
