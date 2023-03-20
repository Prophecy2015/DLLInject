// DebugSetDlg.cpp : 实现文件
//

#include "stdafx.h"
#include "DLLInject.h"
#include "DebugSetDlg.h"
#include "afxdialogex.h"


// CDebugSetDlg 对话框

IMPLEMENT_DYNAMIC(CDebugSetDlg, CDialogEx)

CDebugSetDlg::CDebugSetDlg(CONFIG_INFO stuCfg, CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DLG_PDB, pParent)
	, m_stuCfg(stuCfg)
	, m_strPDBPath(stuCfg.strPDBPath)
	, m_bConsole(stuCfg.iPrintMode == 1)
{

}

CDebugSetDlg::~CDebugSetDlg()
{
}

void CDebugSetDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Text(pDX, IDC_EDIT_PDB_PATH, m_strPDBPath);
	DDX_Radio(pDX, IDC_RADIO_SHAREMEN, m_bConsole);
	DDX_Control(pDX, IDC_COMBO_CODEPAGE, m_ctrlCodePage);
}


BEGIN_MESSAGE_MAP(CDebugSetDlg, CDialogEx)
	ON_BN_CLICKED(IDOK, &CDebugSetDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BTN_BROWSE, &CDebugSetDlg::OnBnClickedBtnBrowse)
END_MESSAGE_MAP()


// CDebugSetDlg 消息处理程序


void CDebugSetDlg::OnBnClickedOk()
{
	// TODO: 在此添加控件通知处理程序代码
	UpdateData();
	m_stuCfg.strPDBPath = m_strPDBPath;
	m_stuCfg.iPrintMode = m_bConsole == TRUE ? 1 : 0;
	m_stuCfg.iCodePage = m_ctrlCodePage.GetItemData(m_ctrlCodePage.GetCurSel());
	CDialogEx::OnOK();
}

BOOL CDebugSetDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	int item = m_ctrlCodePage.AddString(_T("ANSI"));
	m_ctrlCodePage.SetItemData(item, 0);
	item = m_ctrlCodePage.AddString(_T("UTF-8"));
	m_ctrlCodePage.SetItemData(item, 1);

	m_ctrlCodePage.SetCurSel(m_ctrlCodePage.FindString(0, (m_stuCfg.iCodePage == 1) ? _T("UTF-8") : _T("ANSI")));

	UpdateData(FALSE);
	return TRUE;  // return TRUE unless you set the focus to a control
				  // 异常: OCX 属性页应返回 FALSE
}


CONFIG_INFO CDebugSetDlg::GetConfigParam()
{
	return m_stuCfg;
}

void CDebugSetDlg::OnBnClickedBtnBrowse()
{
	UpdateData(TRUE);
	// TODO: 在此添加控件通知处理程序代码
	//打开文件，获取文件路径名
	TCHAR szPath[_MAX_PATH];
	BROWSEINFO bi;
	bi.hwndOwner = GetSafeHwnd();
	bi.pidlRoot = NULL;
	bi.lpszTitle = _T("Please select the input path");
	bi.pszDisplayName = szPath;
	bi.ulFlags = BIF_RETURNONLYFSDIRS;
	bi.lpfn = NULL;
	bi.lParam = NULL;

	LPITEMIDLIST pItemIDList = SHBrowseForFolder(&bi);

	if (pItemIDList)
	{
		if (SHGetPathFromIDList(pItemIDList, szPath))
		{
			if (!m_strPDBPath.IsEmpty())
			{
				m_strPDBPath += _T(";");
			}
			m_strPDBPath += szPath;
		}

		//use IMalloc interface for avoiding memory leak  
		IMalloc* pMalloc;
		if (SHGetMalloc(&pMalloc) != NOERROR)
		{
			TRACE(_T("Can't get the IMalloc interface\n"));
		}

		pMalloc->Free(pItemIDList);
		if (pMalloc)
			pMalloc->Release();

		UpdateData(FALSE);
	}
}
