
#include "stdafx.h"
#include "tool_functions.h"
#include "output_db.h"
#include "event_record.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "init_collector.h"
#include "time_util.h"
#include "event_record_manager.h"
#include "parameter_index.h"
#include "InterfaceCommon/MSSQLite_LocalOfflineDB_IPC.hpp"
#include "InterfaceCommon/SampleInfoSupport_IPC.hpp"
#include "ThirdPart/cJSON/include/cJSON.h"
#include "InterfaceCommon/NgepRegMgr.h"
#include "process_event_info.h"
#include "InterfaceCommon/PykMgr.h"

std::shared_ptr<MSSqlite_LocalOfflineDB_IPC> m_pMSSql_LocalOfflineDb_ipc;

std::shared_ptr<SampleInfoSupport_IPC> m_pSampleInfoSupport_ipc;
CNgepRegMgr m_Reg;
OutputDb::OutputDb()
{
	
	wstring wstrIpcDb = L"EtwDataDb";
	wstring wstrIpcSample = L"EtwDataSample";
	
	m_Reg.LoadReg();

	std::wstring wstripcDllPath = m_Reg.m_strInstallPath;
#ifdef _WIN64
	wstripcDllPath += L"\\NgepIpcClient64.dll";
#else	
	wstripcDllPath += L"\\NgepIpcClient.dll";
#endif

	m_pMSSql_LocalOfflineDb_ipc = std::make_shared<MSSqlite_LocalOfflineDB_IPC>(wstrIpcDb, wstripcDllPath);

	m_pSampleInfoSupport_ipc = std::make_shared<SampleInfoSupport_IPC>(wstrIpcSample, wstripcDllPath);
}

OutputDb::~OutputDb()
{

}

__int64 FindFirstFileSize(WCHAR* wzTargetPath)
{
	DWORD size = 0;
	__int64 ret_size = 0;
	WIN32_FIND_DATA findData;

	HANDLE hFile = FindFirstFile(wzTargetPath, &findData);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		size = findData.nFileSizeLow;
		FindClose(hFile);
	}

	ret_size = (__int64)size;

	return ret_size;
}

__int64 FileSizeEx(WCHAR* wzTargetPath)
{
	__int64 size = 0;
	LARGE_INTEGER LI;

	//OPEN_EXISTING --> 存在则读取，不存在则打开失败T
	HANDLE hFile = CreateFile(wzTargetPath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		if (GetFileSizeEx(hFile, &LI))
		{
			size = LI.QuadPart;
		}
		CloseHandle(hFile);
	}
	else
	{
		DWORD dwError = GetLastError();
	}

	if (!size)
	{
		return FindFirstFileSize(wzTargetPath);
	}

	return size;
}

BOOL AddCommonHeaderToJson(cJSON* pJsonRoot)
{
	m_Reg.LoadReg();

	String strIP;
	strIP = ToolFunctions::WStringToString(m_Reg.m_strIP);
	cJSON_AddItemToObject(pJsonRoot, "ip_address", cJSON_CreateString(strIP.c_str()));

	String struid;
	struid = ToolFunctions::WStringToString(m_Reg.m_strSkustring);
	cJSON_AddItemToObject(pJsonRoot, "uuid", cJSON_CreateString(struid.c_str()));

	String strMac;
	strMac = ToolFunctions::WStringToString(m_Reg.m_strMAC);
	cJSON_AddItemToObject(pJsonRoot, "mac", cJSON_CreateString(strMac.c_str()));

	String strHostName = ToolFunctions::GetHostName();
	cJSON_AddItemToObject(pJsonRoot, "hostname", cJSON_CreateString(strHostName.c_str()));
	cJSON_AddItemToObject(pJsonRoot, "host_name", cJSON_CreateString(strHostName.c_str()));

	return TRUE;
}

BOOL OutputDb::SendRansomIpc(EventRecord* rec)
{
	BOOL bRet = FALSE;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(rec->m_eventIdentifier);
	cJSON* pJsonRoot = cJSON_CreateObject();
	if (pJsonRoot == NULL)
		return FALSE;

	AddCommonHeaderToJson(pJsonRoot);
	LONGLONG dTime = rec->m_ulTimeStamp / 1000000; //1689837849306618500
	cJSON_AddItemToObject(pJsonRoot, "timestamp", cJSON_CreateNumber(dTime));

	GUID guid = rec->m_dGuid;
	char chGUID[64] = { 0 };
	sprintf_s(chGUID, sizeof(chGUID), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	string strUser = "";
	bool isTrust = false;
	string strProcessname = "";
	string strpProcessPath = "";
	auto iter = process_map::g_umapPid2ProcessInfo.find(rec->m_dwProcessId);
	if (iter != process_map::g_umapPid2ProcessInfo.end())
	{
		strUser = ToolFunctions::WStringToString(iter->second.user);
		auto info = iter->second;
		auto ppid = info.parent_pid;
		std::wstring parentname = L"";
		auto pter = process_map::g_umapPid2ProcessInfo.find(ppid);
		if (pter != process_map::g_umapPid2ProcessInfo.end())
		{
			parentname = pter->second.process_name;
			strpProcessPath = ToolFunctions::WStringToString(pter->second.process_path);
		}

		CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> RuleTrustProcess = ToolFunctions::GetMSBasicInfoNGEPRule()->m_niRuleTrustProcess;
		isTrust = CMSBasicInfo_NGEPRuleMatcher::CheckProcess(RuleTrustProcess, info.process_name, info.process_path, info.commandline, info.md5, info.user, parentname);
		strProcessname = ToolFunctions::WStringToString(info.process_name);
	}

	std::shared_ptr<CMSBasicInfo_NGEPPolicy> NGEPPolicy = ToolFunctions::GetMSBasicInfoNGEPPolicy();
	DWORD nMode = ToolFunctions::GetMode();

	cJSON_AddItemToObject(pJsonRoot, "user", cJSON_CreateString(strUser.c_str()));
	cJSON_AddItemToObject(pJsonRoot, "os_type", cJSON_CreateNumber(1));
	cJSON_AddItemToObject(pJsonRoot, "operation_mode", cJSON_CreateNumber(nMode));
	std::string strPolicyId = NGEPPolicy->m_NGEPPolicy_Common.GetPolicyId();
	cJSON_AddItemToObject(pJsonRoot, "policy_id", cJSON_CreateString(strPolicyId.c_str()));
	cJSON_AddItemToObject(pJsonRoot, "behavior", cJSON_CreateNumber(1));
	cJSON_AddItemToObject(pJsonRoot, "result", cJSON_CreateNumber(1));
	cJSON_AddItemToObject(pJsonRoot, "operating", cJSON_CreateString(""));
	cJSON_AddItemToObject(pJsonRoot, "id", cJSON_CreateString(chGUID));
	cJSON_AddItemToObject(pJsonRoot, "log_name", cJSON_CreateString("RansomewareTrack"));
	cJSON_AddItemToObject(pJsonRoot, "log_category", cJSON_CreateString("File"));
	cJSON_AddItemToObject(pJsonRoot, "event_category", cJSON_CreateString("Malicious"));
	if (isTrust || (nMode == OPERATION_MODE_OPERATE))
	{
		cJSON_AddItemToObject(pJsonRoot, "level", cJSON_CreateNumber(0));
		cJSON_AddItemToObject(pJsonRoot, "event", cJSON_CreateBool(FALSE));
	}
	else
	{
		cJSON_AddItemToObject(pJsonRoot, "event", cJSON_CreateBool(TRUE));
		cJSON_AddItemToObject(pJsonRoot, "level", cJSON_CreateNumber(4));
	}
	cJSON_AddItemToObject(pJsonRoot, "source", cJSON_CreateString("EDR"));

	if (NGEPPolicy->m_netwBehaviourRansomwareETWDATA.nGetTerminate() == 1)
	{
		cJSON_AddItemToObject(pJsonRoot, "terminate", cJSON_CreateNumber(2));
	}
	else
	{
		cJSON_AddItemToObject(pJsonRoot, "terminate", cJSON_CreateNumber(1));
	}


	if (ix != EventRecordManager::GetInstance().m_mapEventStrucp.end())
	{
		cJSON_AddItemToObject(pJsonRoot, "EventName", cJSON_CreateString(ix->first.event_name().c_str()));
	}

	if (rec->m_eventIdentifier.provider_id() == ETWStackWalk)
	{
		String stack_str = ((EventRecordCallstack*)rec)->GetOutputInfo();
		cJSON_AddItemToObject(pJsonRoot, "CallStack", cJSON_CreateString(stack_str.c_str()));
	}

	String strProcessPath = "";
	String strProcessName = "";
	String strProcessMd5 = "";
	std::wstring strProcessNameW = L"";
	{
		cJSON* pArguments = cJSON_CreateObject();

		cJSON_AddItemToObject(pArguments, "source_type", cJSON_CreateString("Host"));
		cJSON_AddItemToObject(pArguments, "process_id", cJSON_CreateNumber(rec->m_dwProcessId));
		cJSON_AddItemToObject(pArguments, "parent_process_name", cJSON_CreateString(strpProcessPath.c_str()));
		for (int i = 0; i < rec->m_vctParameterList.size(); i++)
		{
			const char* parm_name;
			parm_name = json_parameter_name_list[EventRecordManager::GetInstance().m_mapEventStrucp[rec->m_eventIdentifier][i].name];
			String parameter_name(parm_name);
			String parmUtf8;
			parmUtf8 = CPykMgrTemplate<CP_UTF8>(rec->m_vctParameterList[i].s.c_str());
			if (parameter_name == "ProcessPath")
			{
				strProcessPath = CPykMgrTemplate<CP_ACP>(rec->m_vctParameterList[i].s.c_str());
				cJSON_AddItemToObject(pArguments, "process_path", cJSON_CreateString(parmUtf8.c_str()));
			}
			else if (parameter_name == "ProcessName")
			{
				strProcessNameW = rec->m_vctParameterList[i].s;
				strProcessName = CPykMgrTemplate<CP_ACP>(rec->m_vctParameterList[i].s.c_str());
				if (strProcessName.empty())
					return FALSE;
				cJSON_AddItemToObject(pArguments, "process_name", cJSON_CreateString(parmUtf8.c_str()));
			}
			else if (parameter_name == "CommandLine")
			{
				cJSON_AddItemToObject(pArguments, "process_commandline", cJSON_CreateString(parmUtf8.c_str()));
			}
			else if (parameter_name == "MD5")
			{
				strProcessMd5 = CPykMgrTemplate<CP_ACP>(rec->m_vctParameterList[i].s.c_str());
				cJSON_AddItemToObject(pArguments, "md5", cJSON_CreateString(parmUtf8.c_str()));
			}
			else if (parm_name == "FileName")
			{
				cJSON_AddItemToObject(pArguments, "parent_process_name", cJSON_CreateString(parmUtf8.c_str()));
			}
		}

		if (strProcessPath.empty())
		{
			std::string strTemp = CPykMgrTemplate<CP_UTF8>(strProcessNameW.c_str());
			cJSON_AddItemToObject(pArguments, "process_path", cJSON_CreateString(strTemp.c_str()));
		}

		cJSON_AddItemToObject(pJsonRoot, "arguments", pArguments);
	}
	//发送ipc到Ngepservice
	m_pMSSql_LocalOfflineDb_ipc->WriteToOfflineDBByIPC(pJsonRoot);

	if (pJsonRoot != NULL)
	{
		cJSON_Delete(pJsonRoot); // 自动删除pArguments
		pJsonRoot = NULL;
	}

	//样本上报
	bool ret = true;
	if (ToolFunctions::isUploadSample())
	{
		m_Reg.LoadReg();
		String struid;
		struid = ToolFunctions::WStringToString(m_Reg.m_strSkustring);
		Sample_Info pInfo;
		pInfo.SetUUID(struid.c_str());

		char chEventTime[100] = { 0 };
		time_t tm = time(NULL);
		sprintf_s(chEventTime, "%llu", (tm) * 1000);
		pInfo.SetEventTime(chEventTime);
		pInfo.SetFileName(strProcessName.c_str());
		pInfo.SetFilePath(strProcessPath.c_str());
		pInfo.SetMd5(strProcessMd5.c_str());
		pInfo.SetLogId(chGUID);
		pInfo.SetLogName("RansomewareTrack");
		pInfo.SetUser_UTF8(strUser.c_str());

		char chSize[20] = { 0 };
		wstring a = ToolFunctions::StringToWString(strProcessPath);
		__int64 dwFileSize = FileSizeEx((WCHAR*)a.c_str());
		sprintf_s(chSize, _countof(chSize), "%llu", dwFileSize);
		pInfo.SetSize(chSize);
		ret = m_pSampleInfoSupport_ipc->UploadSampleFile(&pInfo, TRUE, L"", -1, ToolFunctions::StringToWString(strUser).c_str());
	}
	return bRet;
}

BOOL OutputDb::SendClientProtection(EventRecord* rec)
{
	BOOL bRet = FALSE;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(rec->m_eventIdentifier);
	cJSON* pJsonRoot = cJSON_CreateObject();
	if (pJsonRoot == NULL)
		return FALSE;

	GUID guid = rec->m_dGuid;
	char chGUID[64] = { 0 };
	sprintf_s(chGUID, sizeof(chGUID), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		guid.Data1, guid.Data2, guid.Data3,
		guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
		guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);

	AddCommonHeaderToJson(pJsonRoot);
	LONGLONG dTime = rec->m_ulTimeStamp / 1000000; //1689837849306618500
	cJSON_AddItemToObject(pJsonRoot, "timestamp", cJSON_CreateNumber(dTime));

	string strUser = "";
	bool isTrust = false;
	string strProcessname = "";
	string strpProcessPath = "";
	auto iter = process_map::g_umapPid2ProcessInfo.find(rec->m_dwProcessId);
	if (iter != process_map::g_umapPid2ProcessInfo.end())
	{
		strUser = ToolFunctions::WStringToString(iter->second.user);
		auto info = iter->second;
		strProcessname = ToolFunctions::WStringToString(info.process_name);
	}

	GUID logguid;
	CoCreateGuid(&logguid);
	char chlogGUID[64] = { 0 };
	sprintf_s(chlogGUID, sizeof(chlogGUID), "%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X",
		logguid.Data1, logguid.Data2, logguid.Data3,
		logguid.Data4[0], logguid.Data4[1], logguid.Data4[2], logguid.Data4[3],
		logguid.Data4[4], logguid.Data4[5], logguid.Data4[6], logguid.Data4[7]);

	cJSON_AddItemToObject(pJsonRoot, "id", cJSON_CreateString(chlogGUID));
	cJSON_AddItemToObject(pJsonRoot, "user", cJSON_CreateString(strUser.c_str()));
	cJSON_AddItemToObject(pJsonRoot, "os_type", cJSON_CreateNumber(1));
	cJSON_AddItemToObject(pJsonRoot, "operation_mode", cJSON_CreateNumber(ToolFunctions::GetMode()));
	cJSON_AddItemToObject(pJsonRoot, "behavior", cJSON_CreateNumber(1));
	cJSON_AddItemToObject(pJsonRoot, "operating", cJSON_CreateString("Terminate"));
	cJSON_AddItemToObject(pJsonRoot, "log_name", cJSON_CreateString("ClientProtection"));
	cJSON_AddItemToObject(pJsonRoot, "log_category", cJSON_CreateString("Client"));
	cJSON_AddItemToObject(pJsonRoot, "event", cJSON_CreateBool(FALSE));
	cJSON_AddItemToObject(pJsonRoot, "event_category", cJSON_CreateString(""));
	cJSON_AddItemToObject(pJsonRoot, "level", cJSON_CreateNumber(1));

	cJSON* pArguments = cJSON_CreateObject();
	bool bTerminate = FALSE;
	bool bStop = FALSE;
	for (int i = 0; i < rec->m_vctParameterList.size(); i++)
	{
		const char* parm_name;
		parm_name = json_parameter_name_list[EventRecordManager::GetInstance().m_mapEventStrucp[rec->m_eventIdentifier][i].name];
		String parameter_name(parm_name);
		if (parameter_name == "Terminate")
		{
			bTerminate = rec->m_vctParameterList[i].d;
		}
		else if (parameter_name == "Stopped")
		{
			bStop = rec->m_vctParameterList[i].d;
		}
	}
	if (!bTerminate)
	{
		return true;
	}
	else
	{
		if (bStop)
		{
			cJSON_AddItemToObject(pJsonRoot, "result", cJSON_CreateNumber(1));
			cJSON_AddItemToObject(pJsonRoot, "terminate", cJSON_CreateNumber(2));
		}

		else
		{
			cJSON_AddItemToObject(pJsonRoot, "result", cJSON_CreateNumber(2));
			cJSON_AddItemToObject(pJsonRoot, "terminate", cJSON_CreateNumber(3));
		}

	}

	std::shared_ptr<CMSBasicInfo_NGEPPolicy> NGEPPolicy = ToolFunctions::GetMSBasicInfoNGEPPolicy();
	cJSON_AddItemToObject(pArguments, "object", cJSON_CreateString(strProcessname.c_str()));
	std::string strPolicyId = NGEPPolicy->m_NGEPPolicy_Common.GetPolicyId();
	cJSON_AddItemToObject(pArguments, "policy_id", cJSON_CreateString(strPolicyId.c_str()));
	std::string strPolicyName = NGEPPolicy->m_NGEPPolicy_Common.GetPolicyName();
	cJSON_AddItemToObject(pArguments, "policy_name", cJSON_CreateString(strPolicyName.c_str()));
	std::string strPolicyTime = NGEPPolicy->m_NGEPPolicy_Common.GetPolicyTime();
	cJSON_AddItemToObject(pArguments, "policy_time", cJSON_CreateString(strPolicyTime.c_str()));
	cJSON_AddItemToObject(pArguments, "log_name", cJSON_CreateString("RansomewareTrack"));
	cJSON_AddItemToObject(pArguments, "log_id", cJSON_CreateString(chGUID));

	m_Reg.LoadReg();

	String strVersion;
	strVersion = ToolFunctions::WStringToString(m_Reg.m_strClientVersion);
	String strDir;
	strDir = ToolFunctions::WStringToString(m_Reg.m_strInstallPath);
	cJSON_AddItemToObject(pArguments, "client_version", cJSON_CreateString(strVersion.c_str()));
	cJSON_AddItemToObject(pArguments, "client_dir", cJSON_CreateString(strDir.c_str()));

	cJSON_AddItemToObject(pJsonRoot, "arguments", pArguments);
	m_pMSSql_LocalOfflineDb_ipc->WriteToOfflineDBByIPC(pJsonRoot);


	if (pJsonRoot != NULL)
	{
		cJSON_Delete(pJsonRoot); // 自动删除pArguments
		pJsonRoot = NULL;
	}
	return bRet;
}

bool OutputDb::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return false;

	// add by zxw on 20191128 裁剪无用的事件
	if (rec->isUseless())
		return true;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(rec->m_eventIdentifier);
	
	if (ix == EventRecordManager::GetInstance().m_mapEventStrucp.end())
		return false;
	
	if (ix->first.event_name() == "RansomTerminate")
	{
		SendClientProtection(rec);
	}
	else if(ix->first.event_name() == "RansomCheck")
	{
		SendRansomIpc(rec);
	}
	return true;
}


