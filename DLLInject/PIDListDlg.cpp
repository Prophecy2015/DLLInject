// PIDListDlg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "DLLInject.h"
#include "PIDListDlg.h"
#include "afxdialogex.h"
#include "TLhelp32.h"

// CPIDListDlg �Ի���

IMPLEMENT_DYNAMIC(CPIDListDlg, CDialogEx)

CPIDListDlg::CPIDListDlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(IDD_DLG_PID, pParent)
	, m_strProcName(_T(""))
	, m_dwSelPID(0)
	, m_strSearch(_T(""))
	, m_bCheckAa(FALSE)
	, m_bCheckABC(FALSE)
{

}

CPIDListDlg::~CPIDListDlg()
{
}

void CPIDListDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_LIST_PID, m_ctrlList);
	DDX_Text(pDX, IDC_EDIT_SEARCH, m_strSearch);
	DDX_Check(pDX, IDC_CHECK_Aa, m_bCheckAa);
	DDX_Check(pDX, IDC_CHECK_ABC, m_bCheckABC);
}


BEGIN_MESSAGE_MAP(CPIDListDlg, CDialogEx)
	ON_BN_CLICKED(IDC_BTN_FRUSH, &CPIDListDlg::OnBnClickedBtnFrush)
	ON_NOTIFY(NM_DBLCLK, IDC_LIST_PID, &CPIDListDlg::OnNMDblclkListPid)
	ON_EN_CHANGE(IDC_EDIT_SEARCH, &CPIDListDlg::OnEnChangeEditSearch)
	ON_BN_CLICKED(IDC_CHECK_Aa, &CPIDListDlg::OnBnClickedCheckAa)
	ON_BN_CLICKED(IDC_CHECK_ABC, &CPIDListDlg::OnBnClickedCheckAbc)
END_MESSAGE_MAP()


// CPIDListDlg ��Ϣ�������


void CPIDListDlg::OnBnClickedBtnFrush()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdatePIDList();
}


void CPIDListDlg::UpdatePIDList()
{
	m_ctrlList.DeleteAllItems();

	// ��ȡȫ������
	HANDLE hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (INVALID_HANDLE_VALUE == hProcessSnap)
	{
		AfxMessageBox(_T("��ȡ���̿���ʧ�ܣ�"));
		return;
	}

	PROCESSENTRY32 pe32 = { sizeof(pe32) };
	BOOL bRet = ::Process32First(hProcessSnap, &pe32);

	while (bRet)
	{
		do 
		{
			if (!m_strSearch.IsEmpty())
			{
				if (m_bCheckABC && CString(pe32.szExeFile).MakeUpper() != CString(m_strSearch).MakeUpper())
				{
					break;
				}

				if (m_bCheckAa && CString(pe32.szExeFile).Find(CString(m_strSearch)) < 0)
				{
					break;
				}

				if (FALSE == m_bCheckAa && FALSE == m_bCheckABC && CString(pe32.szExeFile).MakeUpper().Find(CString(m_strSearch).MakeUpper()) < 0)
				{
					break;
				}
			}

			CString strTmp;
			strTmp.Format(_T("%d"), pe32.th32ProcessID);
			int iItem = m_ctrlList.InsertItem(65535, strTmp);
			m_ctrlList.SetItemText(iItem, 1, pe32.szExeFile);
			m_ctrlList.SetItemData(iItem, pe32.th32ProcessID);
		} while (FALSE);

		bRet = ::Process32Next(hProcessSnap, &pe32);
	}

	::CloseHandle(hProcessSnap);
}

BOOL CPIDListDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��

	ListView_SetExtendedListViewStyle(m_ctrlList.GetSafeHwnd(),
	 ListView_GetExtendedListViewStyle(m_ctrlList.GetSafeHwnd()) | LVS_EX_GRIDLINES | LVS_EX_FULLROWSELECT);

	m_ctrlList.InsertColumn(0, _T("PID"), LVCFMT_LEFT, 50);
	m_ctrlList.InsertColumn(1, _T("��������"), LVCFMT_LEFT, 500);

	UpdatePIDList();

	return TRUE;  // return TRUE unless you set the focus to a control
				  // �쳣: OCX ����ҳӦ���� FALSE
}


void CPIDListDlg::OnNMDblclkListPid(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMITEMACTIVATE pNMItemActivate = reinterpret_cast<LPNMITEMACTIVATE>(pNMHDR);
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	m_strProcName = m_ctrlList.GetItemText(pNMItemActivate->iItem, 1);
	m_dwSelPID = m_ctrlList.GetItemData(pNMItemActivate->iItem);

	OnOK();
	*pResult = 0;
}


void CPIDListDlg::OnEnChangeEditSearch()
{
	// TODO:  ����ÿؼ��� RICHEDIT �ؼ���������
	// ���ʹ�֪ͨ��������д CDialogEx::OnInitDialog()
	// ���������� CRichEditCtrl().SetEventMask()��
	// ͬʱ�� ENM_CHANGE ��־�������㵽�����С�

	// TODO:  �ڴ���ӿؼ�֪ͨ����������
	UpdateData(TRUE);
	UpdatePIDList();
}


void CPIDListDlg::OnBnClickedCheckAa()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(TRUE);
	UpdatePIDList();
}


void CPIDListDlg::OnBnClickedCheckAbc()
{
	// TODO: �ڴ���ӿؼ�֪ͨ����������
	UpdateData(TRUE);
	UpdatePIDList();
}
