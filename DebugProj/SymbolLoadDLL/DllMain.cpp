// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "Misc.h"

typedef long           int32;	/* 32-bit signed integer */
typedef unsigned int   uint;	/* 16 or 32-bit unsigned integer */
typedef unsigned long  uint32;	/* 32-bit unsigned integer */
typedef unsigned short uint16;	/* 16-bit unsigned integer */
typedef unsigned char  byte_t;	/*  8-bit unsigned integer */
typedef unsigned char  uint8;	/* 8-bit unsigned integer */

#define MAX_RECEIVE_BUF 1024  //the max data packet length that would be received
#define MAX_SEND_BUF MAX_RECEIVE_BUF  //the max data packet length that would be sent

								/*
								* user info interface
								*/
typedef struct _USER_INFO {
	char       m_userid[12];   	    //DTU Identify number
	uint32     m_sin_addr;     	    //the ip address of DTU in Internet,maybe a gateway ip addr
	uint16     m_sin_port;     	    //the ip port of DTU in Internet
	uint32     m_local_addr;   	    //the ip address of DTU in local mobile net
	uint16     m_local_port;   	    //the local port of DTU in local mobile net
	char       m_logon_date[20]; 	//the date that the DTU logon 
	char	   m_update_time[20];   //the last date that receive IP packet
	uint8	   m_status;		    //DTU status, on line 1 : offline 0
}user_info;
/*
* user data record interface
* as param when call function do_read_proc()
* m_data_type: if 0 unknown type, 0x01 DTU logon;0x04 invalid command;
* 0x05 DTU receive data successfully;
* 0x0d setup parameters successfully;0x0b query parameters successfully;
* 0x06 disconnect ppp link successfully;0x07 stop send data to DSC successfully;
* 0x08 start to send data to DSC successfully;0x0A flush DTU data in cache successfully;
* 0x09 user data type
*/
typedef struct _USER_DATA_RECORD {
	char       m_userid[12];		        //DTU Identify number
	char       m_recv_date[20];		        //the date that receive data packet
	char       m_data_buf[MAX_RECEIVE_BUF]; //store data packet
	uint16     m_data_len;			        //the data length
	uint8      m_data_type;	                //data type
}data_record;

typedef int (WINAPI *Xstart_net_service)(HWND hWnd, unsigned int wMsg, int nServerPort, char *mess);
typedef int (WINAPI *Xstop_net_service)(char *mess);
typedef int (WINAPI *Xdo_read_proc)(data_record *recdPtr, char *mess, BOOL reply);
typedef int (WINAPI *Xdo_send_user_data)(uint8* userid, uint8*data, uint len, char *mess);
typedef int (WINAPI *XSetWorkMode)(int nWorkMode);
typedef int (WINAPI *XSelectProtocol)(int nProtocol);
typedef uint(WINAPI *Xget_max_user_amount)();
typedef uint(WINAPI *Xget_online_user_amount)();
typedef int (WINAPI *Xget_user_info)(uint8 *userid, user_info *infoPtr);
typedef int (WINAPI *Xget_user_at)(uint index, user_info *infoPtr);
typedef int (WINAPI *Xdelete_one_user)(uint8* userid, char *mess);
typedef int (WINAPI *Xdo_close_one_user)(uint8* userid, char *mess);
typedef uint32(WINAPI *Xget_custom_ip)();
typedef void (WINAPI *XSet_custom_ip)(uint32 ip);

int WINAPI do_send_user_data_hook(uint8* userid, uint8*data, uint len, char *mess) {
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(do_send_user_data_hook)(userid, data, len, mess);
		if (data != nullptr) {
			DLL_TRACE(_T("向GPRSID:%s 发送数据:%s"), (char*)userid, CMisc::FormatHex((BYTE*)data, len));
		}
		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(do_send_user_data_hook)(userid, data, len, mess);
}

uint WINAPI get_online_user_amount_hook() {
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(get_online_user_amount_hook)();
		DLL_TRACE(_T("获取在綫用戶的個數:%d"), iRet);
		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(get_online_user_amount_hook)();
}

// 13900100048
int WINAPI get_user_info_hook(uint8 *userid, user_info *infoPtr) {
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(get_user_info_hook)(userid, infoPtr);
		if (infoPtr != nullptr) {
			DLL_TRACE(_T("%s:获取用户信息:%s, state:%d"), (char*)userid, infoPtr->m_userid, infoPtr->m_status);
		}
		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(get_user_info_hook)(userid, infoPtr);
}

int WINAPI get_user_at_hook(uint index, user_info *infoPtr) {
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(get_user_at_hook)(index, infoPtr);
		if (infoPtr != nullptr) {
			DLL_TRACE(_T("获取[%d]用户信息:%s, state:%d"), index, infoPtr->m_userid, infoPtr->m_status);
		}
		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(get_user_at_hook)(index, infoPtr);
}

// 数据格式初步分析
// 7b 01 00 10 139xxxxx 
int WINAPI do_read_proc_hook(data_record *recdPtr, char *mess, BOOL reply) {
	if (CMisc::BeginWork())
	{
		auto iRet = CALL_OLD(do_read_proc_hook)(recdPtr, mess, reply);
		if (recdPtr != nullptr) {
			char *userid = recdPtr->m_userid;
			if (recdPtr->m_data_type != 0
				//&& userid[0] == '1' && userid[8] == '0' && userid[9] == '4' && userid[10] == '8'
				)
			{
				DLL_TRACE(_T("读取到数据类型为0x%X的数据(0x01-注册包、心跳包；0x09-数据包)"), recdPtr->m_data_type);
				if (recdPtr->m_data_type == 0x01) 
				{
					DLL_TRACE(_T("读取到心跳/注册包，用户ID:%s"), recdPtr->m_userid);
				}
				else if (recdPtr->m_data_type == 0x09) 
				{
					DLL_TRACE(_T("读取到数据包，用户ID:%s，数据长度:%d"), recdPtr->m_userid, recdPtr->m_data_len);
					if (recdPtr->m_data_len > 0 && recdPtr->m_data_buf != nullptr)
					{
						DLL_TRACE(_T("\t数据内容：%s"), CMisc::FormatHex((BYTE*)recdPtr->m_data_buf, recdPtr->m_data_len));
					}
				}
			}
		}
		CMisc::EndWork();
		return iRet;
	}

	return CALL_OLD(do_read_proc_hook)(recdPtr, mess, reply);
}

#define WCOMM_DLL _T("wcomm.dll")

extern "C" void DoDebugWork()
{
	// 测试查找符号
	//PVOID get_max_user_amount = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("get_max_user_amount"));
	//PVOID get_online_user_amount = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("get_online_user_amount"));
	//PVOID do_read_proc = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("do_read_proc"));
	//PVOID get_user_info = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("get_user_info"));
	//PVOID get_user_at = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("get_user_at"));
	//PVOID do_close_one_user = CMisc::GetExportFunctionsVa(_T("wcomm_0.dll"), _T("do_close_one_user"));

	// 监听调用
	BEGIN_TRANSACTION;
	DETOUR_ATTACH_SYMBOL(WCOMM_DLL, _T("do_read_proc"), do_read_proc_hook);
	DETOUR_ATTACH_SYMBOL(WCOMM_DLL, _T("get_user_info"), get_user_info_hook);
	DETOUR_ATTACH_SYMBOL(WCOMM_DLL, _T("get_user_at"), get_user_at_hook);
	//DETOUR_ATTACH_SYMBOL(WCOMM_DLL, _T("get_online_user_amount"), get_online_user_amount_hook);
	DETOUR_ATTACH_SYMBOL(WCOMM_DLL, _T("do_send_user_data"), do_send_user_data_hook);
	END_TRANSACTION;
	
}

extern "C" void EndDebugWork() {}

