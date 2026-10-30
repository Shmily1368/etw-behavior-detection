#pragma once
#include "TH_RecordConfigBase.h"
#include "PykMgr.h"
#include <iostream>
#include <fstream>
class CTHMNetworkCallBackRecorder :public::CTHRecordConfigBase
{
public:
	CTHMNetworkCallBackRecorder()
		:CTHRecordConfigBase(L"THMNetworkCallBackRecord.ini", L"THMNetworkCallBack")
	{
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"tcpConnected", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"tcpClosed", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"udpCreated", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"udpClosed", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"dataAvailable", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"udpPostSend", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"ipReceive", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"ipSend", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"HttpRequest", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"HttpResponse", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"SslHandshakeOut", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"dataPartAvailable", FALSE));
		m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
			(L"udpPostReceive", FALSE));

		TCHAR szPath[4096 + 1] = { 0 };
		GetModuleFileName(NULL, szPath, 4096);
		PathRemoveFileSpec(szPath);
		PathAppend(szPath, L"OpenWeb.bat");
		std::string strT = CPykMgrTemplate<CP_ACP>(szPath);
		std::ofstream ofs;
		ofs.open(strT.c_str(), std::ios::out);
		ofs << "start https://www.baidu.com" << std::endl;
		ofs.close();
	}

	~CTHMNetworkCallBackRecorder()
	{

	}
};

class CTHMFileSysMsgRecorder :public::CTHRecordConfigBase
{
public:
	CTHMFileSysMsgRecorder()
		:CTHRecordConfigBase(L"THMFileSysMsgRecord.ini", L"THMFileSysMsg")
	{
	}

	~CTHMFileSysMsgRecorder()
	{

	}
};