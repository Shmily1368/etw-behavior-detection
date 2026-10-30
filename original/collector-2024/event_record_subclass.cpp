#include "stdafx.h"
#include "event_record_subclass.h"
#include "init_collector.h"
#include "get_signature_info.h"
#include "tool_functions.h"
#include "certificate_tool.h"
#include "global_enum_def.h"
#include "tool_functions.h"
#include "time_util.h"
#include "init_collector_online_parse.h"
#include "thread_task_manager.h"

#include  <io.h>
#include <utility>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <boost/regex.hpp>

#include "filter.h"
#include "get_device_drive_map.h"
#include "obtain_entry_address.h"
#include "callstack_pruning.h"
#include "process_info.h"
#include "named_pipe_client.h"
#include "event_record_pruner.h"
#include "task_queue_service.h"
#include "system_call_detector.h"
#include "setting.h"
#include "rule_matcher.h"
#include "zone_identifier.h"
#include "DllUnit.h"
#include "RansomCheck.h"
#include "RegistryUnit.h"
#include "event_record_callstack.h"
#include "process_event_info.h"

std::unordered_map<DWORD, DWORD> EventRecord::m_umapTid2Pid;
std::vector<DWORD> EventRecord::m_vctProcessorId2TidList;
std::unordered_map<DWORD, std::wstring> EventRecord::m_umapPid2ProcessName;
std::unordered_map<DWORD, ULONG64> EventRecord::m_umapPid2NetworkTime;
//MapAutoCleanup<ULONG64, std::wstring>EventRecordRegistry::key_handle2key_name_map;
MapAutoCleanup<std::wstring, std::wstring>EventRecordRegistry::key_handle2key_name_map;
std::unordered_map<DWORD, std::wstring>EventRecordRegistry::thread2_keyname;
std::vector<bool> EventRecordRegistry::isroot_match{ false,false,false,false,false};  //judge if root path is matched 
wstring  EventRecordRegistry::s_openKeyName = L"";
wstring  EventRecordRegistry::s_openKeyHandle = L"";
wstring  EventRecordRegistry::s_createKeyName = L"";
wstring  EventRecordRegistry::s_createKeyHandle = L"";
wstring  EventRecordRegistry::s_createKey = L"";

std::list<EventRecordAlpc::AlpcMessage> EventRecordAlpc::send_message_list_;
//MapAutoCleanup<ULONG64, std::wstring>EventRecordFileio::file_key2file_name_map;
//MapAutoCleanup<ULONG64, std::wstring>EventRecordFileio::file_object2file_name_map;
std::unordered_map<ULONG64, FileIoInfo>EventRecordFileio::file_key2file_info_map;
std::unordered_map < ULONG64, FileIoInfo>EventRecordFileio::file_object2file_info_map;
std::unordered_map<ULONG64, EventRecordFileio*> EventRecordFileio::fileiorename_cache_map;
std::unordered_map<ULONG64, std::wstring> EventRecordFileio::file_context;
long EventRecordFileio::parse_num = 0;
ULONG64 EventRecordFileio::collector_pid = -1;
uint_32 EventMacroResult::_parse_counter = 0;
std::unordered_map<std::wstring, int_32> EventMacroResult::_detected_macro_file_record_map;

const vector<std::wstring> vec_black_list_ransom {
	L"\\cmd.exe",
	L"\\powershell.exe",
	L"\\explorer.exe"
};

bool IsRunasAdmin(DWORD processid) {
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processid);
	if (hProcess == NULL)
		return false;

	BOOL bElevated = FALSE;
	HANDLE hToken = NULL;

	// Get target process token
	if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken))
	{
		CloseHandle(hProcess);
		return false;
	}

	TOKEN_ELEVATION tokenEle;
	DWORD dwRetLen = 0;

	// Retrieve token elevation information
	if (GetTokenInformation(hToken, TokenElevation, &tokenEle, sizeof(tokenEle), &dwRetLen))
	{
		if (dwRetLen == sizeof(tokenEle))
		{
			bElevated = tokenEle.TokenIsElevated;
		}
	}
	else
	{
		CloseHandle(hProcess);
		CloseHandle(hToken);
		return false;
	}

	CloseHandle(hProcess);
	CloseHandle(hToken);
	return bElevated;

}


//judge whether keyhandle is root 
std::wstring IsKeyhandleRoot(std::wstring path) {
	//std::wstring root;
	//return root;   
	int hit = 0;
	//int index = -1;
	HKEY key = nullptr;
	wstring root_path = L"";
	LPCTSTR data = path.c_str();
    // if path is begin with "S-" only RegOpenKeyEx HKEY_USERS
    if (path.length() > 2 && path.substr(0, 2) == L"S-") {       
        auto value = RegOpenKeyEx(HKEY_USERS, data, 0, KEY_QUERY_VALUE, &key);
        if (value == ERROR_SUCCESS) {
			RegCloseKey(key);
            return L"\\REGISTRY\\USER";
        }
        return L"";
    }

	do 
	{
		LSTATUS value = RegOpenKeyEx(HKEY_LOCAL_MACHINE, data, 0, KEY_QUERY_VALUE, &key);
		if (value == ERROR_SUCCESS/* && !EventRecordRegistry::isroot_match[0]*/) {
			hit++;
			//index = 0;
			root_path = L"\\REGISTRY\\MACHINE";
			break;
		}

		value = RegOpenKeyEx(HKEY_CLASSES_ROOT, data, 0, KEY_QUERY_VALUE, &key);
		if (value == ERROR_SUCCESS/* && !EventRecordRegistry::isroot_match[1]*/) {
			hit++;
			//index = 1;
			root_path = L"\\REGISTRY\\CLASSES_ROOT";
			break;
		}

		value = RegOpenKeyEx(HKEY_CURRENT_USER, data, 0, KEY_QUERY_VALUE, &key);
		if (value == ERROR_SUCCESS/* && !EventRecordRegistry::isroot_match[2]*/) {
			hit++;
			//index = 2;
			root_path = L"\\REGISTRY\\CURRENT_USER";
			break;
		}

		value = RegOpenKeyEx(HKEY_USERS, data, 0, KEY_QUERY_VALUE, &key);
		if (value == ERROR_SUCCESS/* && !EventRecordRegistry::isroot_match[3]*/) {
			hit++;
			//index = 3;
			root_path = L"\\REGISTRY\\USER";
			break;
		}

		value = RegOpenKeyEx(HKEY_CURRENT_CONFIG, data, 0, KEY_QUERY_VALUE, &key);
		if (value == ERROR_SUCCESS/* && !EventRecordRegistry::isroot_match[4]*/) {
			hit++;
			//index = 4;
			root_path = L"\\REGISTRY\\CURRENT_CONFIG";
			break;
		}

	} while (FALSE);
	

	RegCloseKey(key);
	if (hit == 1) {
		//EventRecordRegistry::isroot_match[index] = true;
		return root_path;
	}
	else
		return L"";
}

void EventRecordThread::InitFrom(EventRecord* origin)
{
	EventRecord::InitFrom(origin);
	_owner_pid = dynamic_cast<EventRecordThread*>(origin)->_owner_pid;
}

void EventRecordThread::InitParse()
{
	if (m_eventIdentifier.opcode() == EM_ThreadEventOPC::ThreadEnd)
	{
		m_dwProcessId = (DWORD)GetDataParameter(parameter_index_enum::ProcessId);
		//thread_id_ = GetDataParameter(parameter_index_enum::TThreadId);
	}
}

/**
 *  @date       2018/12/28
 *  @brief      解析ThreadProcess event事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordThread::parse()
{
	int event_opcode = m_eventIdentifier.opcode();
	switch (event_opcode)
	{
	case EM_ThreadEventOPC::ThreadStart:
	case EM_ThreadEventOPC::ThreadDCStart:
		//thread_id2process_id_map_.insert(std::pair<DWORD, DWORD>((DWORD)GetDataParameter(parameter_index_enum::TThreadId), process_id_));
        /*  mod by zxw on 20200108
		if(InitCollector::GetCollector() && InitCollector::GetCollector()->GetDetectorMode() == LocalDetectorMode::LOCAL_DETECTOR_MODE__SYSCALL)
			thread_id2process_id_map_.insert(std::pair<DWORD, DWORD>(GetDataParameter(parameter_index_enum::TThreadId), GetDataParameter(parameter_index_enum::ProcessId)));
		else 
			thread_id2process_id_map_.insert(std::pair<DWORD, DWORD>((DWORD)GetDataParameter(parameter_index_enum::TThreadId), process_id_));
        */
        // add by zxw on 20200811
        Filter::GetInstance().OnThreadStart(this);

		m_umapTid2Pid.insert(std::pair<DWORD, DWORD>(GetDataParameter(parameter_index_enum::TThreadId), GetDataParameter(parameter_index_enum::ProcessId)));
		
		if (_owner_pid != m_dwProcessId)
		{
			EventRecordPruner::GetInstance().CleanProcessCache(_owner_pid);
		}
		break;
	case EM_ThreadEventOPC::ThreadEnd:
	{
		DWORD tid = (DWORD)GetDataParameter(parameter_index_enum::TThreadId);
        // add by zxw on 20200811
        Filter::GetInstance().OnThreadEnd(tid, m_dwProcessId);

		m_umapTid2Pid.erase(tid);
        // add by zxw on 20200706
        EventRecordRegistry::thread2_keyname.erase(tid);
        // ADD BY ZXW ON 20200721
        PhfDetector::GetInstance().NotifyThreadEnd(tid);
		break;
	}
	case EM_ThreadEventOPC::ThreadContextSwitch:
		m_bUseless = true;
		while (m_nProcessorId >= m_vctProcessorId2TidList.size())
			m_vctProcessorId2TidList.push_back(0);
		m_vctProcessorId2TidList[m_nProcessorId] = (DWORD)GetDataParameter(parameter_index_enum::NewThreadId);
		break;
	}
	return 0;
}

EventRecordThread::EventRecordThread(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
	, _owner_pid(raw_rec->EventHeader.ProcessId)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordThread);
}

EventRecordThread::~EventRecordThread()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordThread);
}

void EventRecordProcess::InitParse()
{
	int_32 opcode = m_eventIdentifier.opcode();
	if (opcode == EM_ProcessEventOPC::ProcessStart || opcode == EM_ProcessEventOPC::ProcessDCStart)
	{
		m_dwProcessId = GetDataParameter(parameter_index_enum::ParentId);
	}
}

/**
 *  @date       2018/12/28
 *  @brief      解析RecordProcess event事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */

int EventRecordProcess::parse()
{
	int event_opcde = m_eventIdentifier.opcode();
	bool result;
	DWORD dwCurrentPid = GetDataParameter(parameter_index_enum::ProcessId);
	DWORD dwParentPid = m_dwProcessId;
	std::wstring file_name = GetStringParameter(parameter_index_enum::ImageFileName);
	const std::wstring commandline = GetStringParameter(parameter_index_enum::CommandLine);
	switch (event_opcde)
	{
	case EM_ProcessEventOPC::ProcessStart:
	case EM_ProcessEventOPC::ProcessDCStart:
		if (HasUnicodeName(commandline))
		{
			file_name = GetProcessName(commandline);
			SetParameter(parameter_index_enum::ImageFileName, file_name);
		}
		m_umapPid2ProcessName.insert(std::pair<DWORD, std::wstring>(dwCurrentPid, file_name));
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].reset();
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].parent_pid = dwParentPid;
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].process_name = file_name;
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].commandline = commandline;
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].m_bExisted = true;

        m_umapPid2NetworkTime.insert(std::pair<DWORD, ULONG64>(dwCurrentPid, 0));

		result = IsRunasAdmin(dwCurrentPid);
		{
			auto userSID = GetStringParameter(parameter_index_enum::UserSID);

			process_map::g_umapPid2ProcessInfo[dwCurrentPid].user = userSID;

			if (RansomCheck::getDetectFlag())
			{
				if (StringUtil::IsStartWith(userSID, L"nt authority", true))
				{
					RansomCheck::addSystemProcess(dwCurrentPid);
				}
			}
			SetParameter(parameter_index_enum::UserSID, userSID + L"&" + std::to_wstring(result));
		}
		if (InitCollector::GetCollector()->insert_child_process() && Filter::query_process_id_white_list(dwParentPid))
		{
			Filter::insert_process_id_white_list(dwCurrentPid);
		}

		if (Filter::query_process_id_black_list(m_dwProcessId))
		{
			Filter::insert_process_id_black_list(dwCurrentPid);
		}

		

        // add by zxw on 20200814 
        Filter::GetInstance().OnProcessStart(this);
		// add by zxw on 20191122 添加父子进程关系map
		//Filter::insert_processid_parentid_map(pid, GetDataParameter(parameter_index_enum::ParentId));

		if ((event_opcde == EM_ProcessEventOPC::ProcessDCStart 
			|| event_opcde == EM_ProcessEventOPC::ProcessStart) && file_name.find(L"ApplicationFrameHost.exe") != std::wstring::npos)
		{
			InitCollectorOnlineParse::m_dwApplicationFrameHostPid = dwCurrentPid;
		}

#ifndef STANDALONE_COLLECTOR
		//for scheduler communicate 
		if (m_nPid != 0 && m_nPid != 4)
		{
			ProcessInfoItem item(m_nPid, m_ulTimeStamp, m_dwProcessId, file_name);
			item.TranslateQPCtimeToSystime();
			ProcessInfo::process_info[m_nPid] = item;
		}
#endif
		break;
	case EM_ProcessEventOPC::ProcessEnd:

		if (RansomCheck::getDetectFlag())
		{
			RansomCheck::removeProcess(dwCurrentPid);
			Filter::remove_registry_pid_white_list(dwCurrentPid);
		}

		process_map::g_umapPid2ProcessInfo[dwCurrentPid].m_bExisted = false;
		//process_map::g_umapPid2ProcessInfo.erase(pid);

		if (m_umapPid2ProcessName.count(dwCurrentPid) != 0)
		{
			m_umapPid2ProcessName.erase(dwCurrentPid);
		}

        if (m_umapPid2NetworkTime.count(dwCurrentPid) != 0) {
            m_umapPid2NetworkTime.erase(dwCurrentPid);
        }

        // REMOVE BY ZXW ON 20200525 do not send,scheduler not deal it
        /*
#ifndef STANDALONE_COLLECTOR
		////for scheduler communicate 
		ProcessInfoItem item(pid, time_stamp_);
		item.TranslateQPCtimeToSystime();
		NamedPipeClient::GetInstance().WritePipe(item);
#endif
        */

		//when process end , should release tree struct (module's rva still save in DLLmodualTree
		if (ObtainEntryAddress::m_moduleAddressTree[dwCurrentPid % Max_Process_ID])
		{
			ObtainEntryAddress::m_moduleAddressTree[dwCurrentPid % Max_Process_ID]->destroy_tree();
			//ObtainEntryAddress::moduleAddressTree[process_id_ % Max_Process_ID] = NULL;
			// add by zxw on 20191128 数据积压内存泄漏
			delete ObtainEntryAddress::m_moduleAddressTree[dwCurrentPid % Max_Process_ID];
			ObtainEntryAddress::m_moduleAddressTree[dwCurrentPid % Max_Process_ID] = nullptr;
		}
	
		ObtainEntryAddress::m_umapExeNode.erase(dwCurrentPid);

		//optimize,fix chips, package one function
		EventRecordCallstack::process_address_cache.erase(dwCurrentPid);
		EventRecordCallstack::process_API_address_cache.erase(dwCurrentPid);
		EventRecordCallstack::process_address_useless_cache.erase(dwCurrentPid);
		EventRecordCallstack::APIaddress_keepon_cache.erase(dwCurrentPid);

		if (Filter::GetInstance().query_process_id_black_list(dwCurrentPid))
		{
			Filter::GetInstance().remove_process_id_black_list(dwCurrentPid);
		}
		Filter::GetInstance().OnProcessEnd(dwCurrentPid);

		// add by zxw on 20191122 移除加父子进程关系map
		//Filter::erase_processid_parentid_map(pid);

		EventRecordPruner::GetInstance().OnProcessEnd(dwCurrentPid);

		break;
	}

//#ifdef ETW_HASH_TEST
//	this->Record2csv("EventRecordProcess_parse");
//#endif // ETW_HASH_TEST
	return 0;
}

bool EventRecordProcess::Output()
{
	DWORD dwCurrentPid = GetDataParameter(parameter_index_enum::ProcessId);
	DWORD dwParentPid = m_dwProcessId;

	QPCtimeToSystime();

	EM_ProcessEventOPC op_code = (EM_ProcessEventOPC)get_event_identifier_().opcode();
	if (op_code == EM_ProcessEventOPC::ProcessStart || op_code == EM_ProcessEventOPC::ProcessDCStart)
	{
		PhfDetector::GetInstance().NotifyProcessStart(GetDataParameter(parameter_index_enum::ParentId)
			, GetStringParameter(parameter_index_enum::ImageFileName)
			, get_time_stamp_());
		/*if (event_record->GetStringParameter(parameter_index_enum::ImageFileName) == L"server.exe")
			dest_pid = event_record->GetDataParameter(parameter_index_enum::ProcessId);*/

        // add by zxw on 20201012
        if (rule_matcher::GetInstance().exist_rule(m_eventIdentifier))
        {
            EventRecord* temp = new EventRecordProcess;
            copy(temp);
            auto it = m_umapPid2ProcessName.find(m_dwProcessId);
            if (it != m_umapPid2ProcessName.end())
                temp->SetParameter(parameter_index_enum::ParentProcessName, m_umapPid2ProcessName[m_dwProcessId]);
            if (ThreadTaskManager::GetInstance().AddEventRecord(RULE_MATCHER_TASK_MODE, temp) == false) {
                SAFE_DELETE(temp);
            }
        }     

		process_map::g_umapPid2ProcessInfo[dwCurrentPid].start_QPCtime = get_time_stamp_();
	}
	else if (op_code == EM_ProcessEventOPC::ProcessEnd || op_code == EM_ProcessEventOPC::ProcessDCEnd)
	{
		PhfDetector::GetInstance().NotifyProcessEnd(GetDataParameter(parameter_index_enum::ProcessId), get_time_stamp_());
		ThreadTaskManager::GetInstance().AddEventRecord(EM_ThreadTaskMode::GET_VISIBLE_WINDOW_TASK_MODE, this);
		process_map::g_umapPid2ProcessInfo[dwCurrentPid].m_bExisted = false;
		//process_map::g_umapPid2ProcessInfo.erase(dwCurrentPid);
	}
//#ifdef ETW_EVENT_RECORD_TEST	
//	Record2csv("EventRecordProcess");
//#endif
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);
	return true;
}

EventRecordProcess::EventRecordProcess() 
{
    OBJECT_MEMORY_MONITOR_CTOR(EventRecordProcess);
}

EventRecordProcess::EventRecordProcess(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordProcess);
//#ifdef ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST	
//	InitCollectorOnlineParse::RecordEvent(raw_rec);
//#endif
}

EventRecordProcess::~EventRecordProcess()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordProcess);
}

bool EventRecordProcess::HasUnicodeName(const std::wstring& command)
{
	static const boost::wregex re(L"[\u4e00-\u9fa5]+.*\.exe", boost::regex_constants::icase);
	boost::wsmatch match;
	if (boost::regex_search(command, match, re, boost::match_flag_type::match_stop)) {
		return true;
	}
	return false;
}

std::wstring EventRecordProcess::GetProcessName(const std::wstring& command)
{
	auto name = command.substr(0, command.find(L".exe"));
	name = ToolFunctions::GetAppNamefromPath(name);
	name.append(L".exe");
	return name;
}

void EventRecordFileio::GetLastWrittenInterval() 
{
	//unused;
	//SYSTEMTIME time;
	WIN32_FILE_ATTRIBUTE_DATA lpinf;
	wstring file_name = GetStringParameter(parameter_index_enum::FileName);
	//string path = ToolFunctions::WStringToString(file_name);
	GetFileAttributesEx(file_name.c_str(), GetFileExInfoStandard, &lpinf);
	FILETIME ft = lpinf.ftLastWriteTime;

	ULONG64 current_tics = (unsigned __int64)ft.dwLowDateTime + (((unsigned __int64)ft.dwHighDateTime) << 32) - EPOCHFILETIME;
	LONG64 time_gap = (m_ulTimeStamp / 100 - current_tics) / 10000000;  //s
	SetParameter(parameter_index_enum::TimeDateStamp, time_gap);
}

EventRecordRegistry::EventRecordRegistry(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordRegistry);
}

EventRecordRegistry::~EventRecordRegistry()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordRegistry);
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordRegistry event 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordRegistry::parse()
{
	if (Filter::query_registry_pid_white_list(m_dwProcessId)) return 0;
	int event_opcode = m_eventIdentifier.opcode();
	switch (event_opcode)
	{
        case EM_RegistryEventOPC::RegistryOpen:
        {
            ParseRegistryOpen();
            break;
        }
		case EM_RegistryEventOPC::RegistryKCBCreate:  //RegistryKCBCreate
		{
            ParseRegistryKCBCreate();
			break;
		}
		case EM_RegistryEventOPC::RegistryKCBDelete:  //RegistryKCBDelete,do not deal it 
			break;      
		case EM_RegistryEventOPC::RegistryCreate:
		//case EM_RegistryEventOPC::RegistryOpen:
		//case EM_RegistryEventOPC::RegistryQueryValue:
		//case EM_RegistryEventOPC::RegistryRegistrySetValuee:
		{
            ParseRegistryCreate();
			break;
		}
        case EM_RegistryEventOPC::RegistryRegistrySetValuee:
        {
            ParseRegistrySetValue();
            break;
        }
		case EM_RegistryEventOPC::RegistryQuery: 
        {  
            //ParseRegistryQuery();
			break;
		}
        case EM_RegistryEventOPC::RegistryClose:
        {
            ParseRegistryClose();
            break;
        }
        case EM_RegistryEventOPC::RegistryDelete:              
        {
            ParseRegistryDelete();
            break;
        }
        case EM_RegistryEventOPC::RegistryDeleteValue:
        {
            ParseRegistryDeleteValue();
            break;
        }
		default:
			break;

	}
	return 0;
}
// add by zxw on 20200420
/*
bool EventRecordRegistry::Output()
{
    // prune KeyName contain "\\REGISTRY\\A\\"
    auto keyname = GetStringParameter(parameter_index_enum::KeyName);
    if (keyname.length() > 12 && keyname.substr(0, 12) == L"\\REGISTRY\\A\\")
    {      
        return false;
    }   

    bool flag = true;
    int event_opcode = event_identifier_.opcode();
    switch (event_opcode)
    {
    case EM_RegistryEventOPC::RegistryCreate:
    {
        // prun
        if (keyname.length() > 0 && EventRecordPruner::GetInstance().PrunRegistryEvent(this)) {
            return false;
        }
    }
        break;
    case EM_RegistryEventOPC::RegistrySetInformation:
    case EM_RegistryEventOPC::RegistryOpen:
    case EM_RegistryEventOPC::RegistryQueryValue:
    case EM_RegistryEventOPC::RegistryQuery:
    case EM_RegistryEventOPC::RegistryClose:
    {
        // add by zxw on 20200519
        if (!Setting::GetInstance().enable_debug_output())
            flag = false;
    }
        break;

    default:
        break;
    }

    if (flag)
    {
        QPCtimeToSystime();
        if (InitCollector::GetCollector())
            InitCollector::GetCollector()->PushSendRecord(this);
        return true;
    }
    return false;
}
*/

bool EventRecordRegistry::Output()
{
#ifdef ETW_EVENT_RECORD_TEST
	std::string strTemp = CPykMgrTemplate<CP_ACP>(this->m_vctParameterList.back().s.c_str());
	this->Record2csv(strTemp);
#endif // ETW_EVENT_RECORD_TEST	
	if (RansomCheck::getDetectFlag())
	{
		auto opcode = m_eventIdentifier.opcode();

		if (opcode == EM_RegistryEventOPC::RegistryOpen 
			|| opcode == EM_RegistryEventOPC::RegistryClose) 
			return false;

		auto pFun = [](DWORD dwPid
			, std::wstring strReg
			, int nType)
		{
			RegistryUnit::increase(dwPid, (registryops)nType);
			if (!strReg.empty())
			{
				std::string strTemp = CPykMgrTemplate<CP_ACP>(strReg.c_str());
				EventRecordRegistryPathClassification::InsertRegistry(dwPid, strTemp
					, (EventRecordRegistryPathClassification::RegistryOperationType)nType);
			}
		};

		switch (opcode)
		{
		case EM_RegistryEventOPC::RegistryCreate:
		case EM_RegistryEventOPC::RegistryKCBCreate:
			pFun(m_dwProcessId, this->m_vctParameterList.back().s, (int)registryops::createops);
			break;
		case EM_RegistryEventOPC::RegistryDelete:
		case EM_RegistryEventOPC::RegistryDeleteValue:
		case EM_RegistryEventOPC::RegistryKCBDelete:
			pFun(m_dwProcessId, this->m_vctParameterList.back().s, (int)registryops::deleteops);
			break;
		case EM_RegistryEventOPC::RegistryQuery:
		case EM_RegistryEventOPC::RegistryQueryValue:
			pFun(m_dwProcessId, this->m_vctParameterList.back().s, (int)registryops::queryops);
			break;
		case EM_RegistryEventOPC::RegistryRegistrySetValuee:
		case EM_RegistryEventOPC::RegistrySetInformation:
			pFun(m_dwProcessId, this->m_vctParameterList.back().s, (int)registryops::setops);
			break;
		default:
			break;
		}
		return false;
	}
	return false;
}
//
void EventRecordRegistry::ParseRegistryKCBCreate() 
{
    if (wcslen(GetStringParameter(parameter_index_enum::KeyName).c_str()) != 0) {
        auto key = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(m_dwProcessId);
        key_handle2key_name_map.SetValue(key, GetStringParameter(parameter_index_enum::KeyName));
    }
}

void EventRecordRegistry::ParseRegistryCreate() 
{
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    wstring create_key = GetStringParameter(parameter_index_enum::KeyName);
    // if last ParseRegistryCreate KeyName = this return   
    if (s_createKeyHandle == handle && s_createKeyName == create_key) {
        if (s_createKey != create_key)
        {
            SetParameter(parameter_index_enum::KeyName, s_createKey);
        }       
        return;
    }

    s_createKeyHandle = handle;
    s_createKeyName = create_key;

    //ULONG64 handle = GetDataParameter(parameter_index_enum::KeyHandle);
    wstring parent_keyname = key_handle2key_name_map.GetValue(handle);  
    DWORD status = GetDataParameter(parameter_index_enum::Status);

    // add by zxw on 20200703 reduce data completion error
    if (handle.substr(0, 1) != L"0" && create_key.length() > 2 && create_key.substr(0, 2) == L"S-" && parent_keyname != L"\\REGISTRY\\USER") 
    {
        HKEY key = nullptr;
        auto value = RegOpenKeyEx(HKEY_USERS, create_key.c_str(), 0, KEY_QUERY_VALUE, &key);
        if (value == ERROR_SUCCESS) {
            wstring root_path = L"\\REGISTRY\\USER";
            key_handle2key_name_map.SetValue(handle, root_path);
            SetParameter(parameter_index_enum::KeyName, root_path + L"\\" + create_key);
			WriteLog4cPlus(DEBUG_LEVEL, L"TEST EventRecordRegistry::ParseRegistryCreate parent_keyname: %s handle: %s", parent_keyname.c_str(), handle.c_str());
			RegCloseKey(key);
            return;
        }
    }

    //match key handle to lastest key name 
    if (handle.substr(0, 1) != L"0" && wcslen(parent_keyname.c_str()) == 0) {
        auto iter = thread2_keyname.find(m_dwThreadId);
        if (iter != thread2_keyname.end()) {
            key_handle2key_name_map.SetValue(handle, iter->second);
            parent_keyname = iter->second;
            thread2_keyname.erase(iter);
        }
    }

    //key handle open pervious is hard to get meaning. So only get root key handle.
    if (wcslen(parent_keyname.c_str()) == 0 && (status == 0) && handle.substr(0, 1) != L"0" && create_key.find(L"\\") != create_key.npos) {
        wstring root_path = IsKeyhandleRoot(create_key);
        if (wcslen(root_path.c_str()) != 0) {
            key_handle2key_name_map.SetValue(handle, root_path);
            parent_keyname = root_path;
        }
    }

    if ((wcslen(parent_keyname.c_str()) != 0 || handle.substr(0, 1) == L"0"))  // we know parent path of key 
    {
        //SetParameter(parameter_index_enum::FileName, file_name);
        std::wstring temp = parent_keyname;      
        auto keysize = create_key.size();
        auto namesize = parent_keyname.size();
        if (keysize != 0)
        {
            // if create_key is the last parent_keyname do not add
            if (!(namesize > keysize && parent_keyname.substr(namesize - keysize) == create_key))
            {
                temp += L"\\";
                temp += create_key;
            }          
        }              

        if (status == 0) {
            if (handle.substr(0, 1) == L"0")
                thread2_keyname[m_dwThreadId] = create_key;
            else {               
                thread2_keyname[m_dwThreadId] = temp;

                SetParameter(parameter_index_enum::KeyName, temp);
            }
        }
        else if (handle.substr(0, 1) != L"0") {
            if ((wcslen(create_key.c_str()) != 0))
                SetParameter(parameter_index_enum::KeyName, temp);
            else
                SetParameter(parameter_index_enum::KeyName, parent_keyname);
        }
    }

    s_createKey = GetStringParameter(parameter_index_enum::KeyName);
}

void EventRecordRegistry::ParseRegistryOpen() 
{   
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    wstring create_key = GetStringParameter(parameter_index_enum::KeyName);   
    // if last RegistryOpen KeyName = this return   
    if (s_openKeyHandle == handle && s_openKeyName == create_key) {      
        return;
    }
   
    s_openKeyHandle = handle;
    s_openKeyName = create_key;

    wstring parent_keyname = key_handle2key_name_map.GetValue(handle);
    DWORD status = GetDataParameter(parameter_index_enum::Status);
    bool isadd = false;

    //match key handle to lastest key name 
    if (handle.substr(0, 1) != L"0" && wcslen(parent_keyname.c_str()) == 0) {
        auto iter = thread2_keyname.find(m_dwThreadId);
        if (iter != thread2_keyname.end()) {
            key_handle2key_name_map.SetValue(handle, iter->second);
            parent_keyname = iter->second;
           // thread2_keyname.erase(iter);
        }
    }

    //match key handle to lastest key name 
    if (handle.substr(0, 1) != L"0" && wcslen(parent_keyname.c_str()) == 0) {
        if (wcslen(create_key.c_str()) != 0 && create_key.find(L"\\") != create_key.npos) {            
            wstring root_path = IsKeyhandleRoot(create_key);
            if (wcslen(root_path.c_str()) != 0) {
                key_handle2key_name_map.SetValue(handle, root_path);
                parent_keyname = root_path;
                auto tmp = parent_keyname;
                tmp += L"\\";
                tmp += create_key;
                thread2_keyname[m_dwThreadId] = tmp;
                isadd = true;              
            }          
        }
        /*
        else {
            auto iter = thread2_keyname.find(thread_id_);
            if (iter != thread2_keyname.end()) {
                key_handle2key_name_map.SetValue(handle, iter->second);
                parent_keyname = iter->second;
                //thread2_keyname.erase(iter);               
            }
          
        }*/
    }
   
    if ((wcslen(parent_keyname.c_str()) != 0 || handle.substr(0, 1) == L"0")) 
    {
        auto tmp = parent_keyname;
        auto keysize = create_key.size();
        auto namesize = parent_keyname.size();
        if (keysize != 0) {
            // if create_key is the last parent_keyname do not add
            if (!(namesize > keysize && parent_keyname.substr(namesize - keysize) == create_key)) {
                tmp += L"\\";
                tmp += create_key;
            }
        }
        /*
        if ((wcslen(create_key.c_str()) != 0)) {
            tmp += L"\\";
            tmp += create_key;
        }
        */
        if (status == 0 && handle.substr(0, 1) == L"0") {
            thread2_keyname[m_dwThreadId] = create_key;
            
        }
        else if (!isadd) 
        {             
            thread2_keyname[m_dwThreadId] = tmp;
            //thread2_keyname[thread_id_] = parent_keyname + L"\\" + create_key;         
        }

        if (handle.substr(0, 1) != L"0") {
            SetParameter(parameter_index_enum::KeyName, tmp);          
        }
    }
}

void EventRecordRegistry::ParseRegistrySetValue() 
{
    //auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(process_id_);
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    wstring parent_keyname = key_handle2key_name_map.GetValue(handle);

    wstring create_key = GetStringParameter(parameter_index_enum::KeyName);
    DWORD status = GetDataParameter(parameter_index_enum::Status);

    //match key handle to lastest key name 
    if (handle.substr(0, 1) != L"0" && wcslen(parent_keyname.c_str()) == 0) {
        auto iter = thread2_keyname.find(m_dwThreadId);
        if (iter != thread2_keyname.end()) {
            key_handle2key_name_map.SetValue(handle, iter->second);
            parent_keyname = iter->second;
            thread2_keyname.erase(iter);
        }
    }

    if (wcslen(parent_keyname.c_str()) != 0)  // we know parent path of key 
    {
        std::wstring temp = parent_keyname;
        if ((wcslen(create_key.c_str()) != 0)) {
            temp += L"\\";
            temp += create_key;
            //temp = parent_keyname + L"\\" + create_key;
        }

        SetParameter(parameter_index_enum::KeyName, temp);
    }
}

void EventRecordRegistry::ParseRegistryClose() 
{
    //auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(process_id_);
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    key_handle2key_name_map.DeleteKey(handle);

    // reset cache
    if (s_openKeyHandle == handle)
    {
        s_openKeyHandle = L"";
        s_openKeyName = L"";
    }
    if (s_createKeyHandle == handle) {
        s_createKeyHandle = L"";
        s_createKeyName = L"";
        s_createKey = L"";
    }  
}

void EventRecordRegistry::ParseRegistryDelete() 
{
    //auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(process_id_);
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    wstring keyname = key_handle2key_name_map.GetValue(handle);
    if (wcslen(keyname.c_str()) != 0) {
        SetParameter(parameter_index_enum::KeyName, keyname);
    }
    else {
        auto iter = thread2_keyname.find(m_dwThreadId);
        if (iter != thread2_keyname.end()) {
            SetParameter(parameter_index_enum::KeyName, iter->second);
        }
    }
}

void EventRecordRegistry::ParseRegistryDeleteValue() 
{
    //auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(process_id_);
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle));
    handle += to_wstring(m_dwProcessId);
    wstring keyname = key_handle2key_name_map.GetValue(handle);
    wstring value_key = GetStringParameter(parameter_index_enum::KeyName);
    if (wcslen(keyname.c_str()) != 0 && wcslen(value_key.c_str()) != 0) {
        keyname += L"\\";
        keyname += value_key;
        SetParameter(parameter_index_enum::KeyName, keyname);
    }
}

void EventRecordRegistry::ParseRegistryQuery() 
{
    /*
    auto handle = to_wstring(GetDataParameter(parameter_index_enum::KeyHandle)) + to_wstring(process_id_);
    //ULONG64 handle = GetDataParameter(parameter_index_enum::KeyHandle);
    wstring keyname = key_handle2key_name_map.GetValue(handle);
    if (wcslen(keyname.c_str()) == 0 && handle.substr(0, 1) != L"0")
    {
        auto iter = thread2_keyname.find(thread_id_);
        if (iter != thread2_keyname.end())
        {
            key_handle2key_name_map.SetValue(handle, iter->second);
            SetParameter(parameter_index_enum::KeyName, iter->second);
            thread2_keyname.erase(iter);
            //useless = true;
        }
    }
    */
}

std::vector<std::pair<int, std::set<std::string>>> EventRecordFileioSuffix::m_vctEnum2SuffixList = {
	{1,{"txt"
		,"doc"
		,"docx"
		,"ppt"
		,"pptx"
		,"xls"
		,"xlsx"
		,"wps"
		,"pdf"
		,"zip"
		,"md"
		,"ini"
		,"exe"}}
	,{2,{"dll"}}
};
std::set<std::string> EventRecordFileioSuffix::m_setSuffixList;

std::vector<std::pair<int, std::string>> EventRecordRegistryPathClassification::m_vctEnum2RegistryPath = {
	{1,"\\Microsoft\\Cryptography\\"}
,{2,"Applications"}
,{3,"\\TypeLib"}
,{4,"\\RestartManager"}
,{5,"\\SOFTWARE\\Microsoft\\Windows\\"}
,{6,"\\Classes\\CLSID\\"}};
int EventRecordRegistryPathClassification::g_nMaxRegistryPathSize = 7;
std::mutex EventRecordRegistryPathClassification::m_mutexPid2RegOptlist;
std::unordered_map<DWORD, std::shared_ptr<std::vector<EventRecordRegistryPathClassification::RegistryUnitOperations>>>
EventRecordRegistryPathClassification::m_umapPid2RegOptlist;

EventRecordFileio::EventRecordFileio(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
	, _file_name(L"")
	, _force_convert_path(false)
{ 
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordFileio);
#ifdef ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST	
	InitCollectorOnlineParse::RecordEvent(raw_rec);
#endif
}

EventRecordFileio::EventRecordFileio()
	: EventRecord()
	, _file_name(L"")
	, _force_convert_path(false)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordFileio);
}

EventRecordFileio::~EventRecordFileio()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordFileio);
}

void EventRecordFileio::InitFrom(EventRecord* origin)
{
	EventRecord::InitFrom(origin);

	EventRecordFileio* origin_t = dynamic_cast<EventRecordFileio*>(origin);
	_file_name = origin_t->_file_name;
	_force_convert_path = origin_t->_force_convert_path;
}

void EventRecordFileio::InitParse()
{
	if (m_dwThreadId == -1)
	{
		if (GetDataParameter(parameter_index_enum::TTID) != 0)
		{
			m_dwThreadId = GetDataParameter(parameter_index_enum::TTID);
			auto ix = m_umapTid2Pid.find(m_dwThreadId);
			m_dwProcessId = ix != m_umapTid2Pid.end() ? ix->second : -1;
		}
		else
		{
			if (m_nProcessorId >= 0 && m_nProcessorId <= 64)   // a tricky design,
			{
				if (m_nProcessorId >= m_vctProcessorId2TidList.size())
				{
					m_dwThreadId = 0;
					m_dwProcessId = 0;
				}
				else
				{
					m_dwThreadId = m_vctProcessorId2TidList[m_nProcessorId];
					auto ix = m_umapTid2Pid.find(m_dwThreadId);
					m_dwProcessId = ix != m_umapTid2Pid.end() ? ix->second : -1;
				}
			}
		}
	}

	switch (m_eventIdentifier.opcode())
	{
	case EM_FileioEventOPC::FileioNameEvent://以前有过这个event，从此再也没抓到过;
	case EM_FileioEventOPC::FileioFileCreateEvent:  //fileiofilecreate
	{
		std::wstring raw_file_name = GetStringParameter(parameter_index_enum::FileName);
		if (GetDataParameter(parameter_index_enum::FileObject) == 0 || wcslen(raw_file_name.c_str()) == 0)
			return;

		std::wstring file_name;
		if (!ObtainEntryAddress::m_drivemap.ConvertDeviceFormat2DriveFormat(raw_file_name, file_name, _force_convert_path) && !_force_convert_path)
		{
			_OnConvertPathError();
		}

		SetParameter(parameter_index_enum::FileName, file_name);
		break;
	}
	case EM_FileioEventOPC::FileioCreateEvent:   //fileiocreate
	{
		std::wstring raw_open_path = GetStringParameter(parameter_index_enum::OpenPath);
		if (GetDataParameter(parameter_index_enum::FileObject) == 0 || wcslen(raw_open_path.c_str()) == 0)
			return;

		std::wstring open_path;
		if (!ObtainEntryAddress::m_drivemap.ConvertDeviceFormat2DriveFormat(raw_open_path, open_path, _force_convert_path) && !_force_convert_path)
		{
			_OnConvertPathError();
		}

		SetParameter(parameter_index_enum::OpenPath, open_path);
		break;
	}
	}
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordFileio event 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordFileio::parse()
{
	// 解析数为200000时开始清理
	if (++parse_num % 200000 == 0)
	{
		wstring str = L"file_context: " + std::to_wstring(file_context.size())+L"\n";
		str += L"file_key2file_name_map: " + std::to_wstring(file_key2file_info_map.size()) + L"\n";
		str += L"file_object2file_info_map: " + std::to_wstring(file_object2file_info_map.size()) + L"\n";
		str += L"fileiorename_cache_map: " + std::to_wstring(fileiorename_cache_map.size()) + L"\n";
		for (auto iter = file_object2file_info_map.begin(); iter != file_object2file_info_map.end(); )
		{
			if (iter->second.used == 0)
			{
				iter = file_object2file_info_map.erase(iter);
			}
			else
			{
				iter->second.used = 0;
				iter++;
			}
		}
		for (auto iter = file_key2file_info_map.begin(); iter != file_key2file_info_map.end(); )
		{
			if (iter->second.used == 0)
			{
				iter = file_key2file_info_map.erase(iter);
			}
			else
			{
				iter->second.used = 0;
				iter++;
			}
		}
		parse_num = 0;
	}

	if (collector_pid == -1)
	{
		collector_pid = GetCurrentProcessId();
	}

	//2018.12.14  chunlin decide do not send System(pid==4) fileioevent
	if (m_dwProcessId == 4)
	{
		m_bUseless = true;
		//return 0;
	}
	if (m_dwProcessId == collector_pid)
	{
		return 0;
	}

	int event_opcode = m_eventIdentifier.opcode();
	switch (event_opcode)
	{
	case EM_FileioEventOPC::FileioNameEvent://以前有过这个event，从此再也没抓到过;
	case EM_FileioEventOPC::FileioFileCreateEvent:  //fileiofilecreate
	{
		std::wstring file_name = GetStringParameter(parameter_index_enum::FileName);
		if (GetDataParameter(parameter_index_enum::FileObject) == 0 || wcslen(file_name.c_str()) == 0)
			return 0;

		FileIoInfo file_info;
		file_info.file_name = file_name;
		file_info.used = 1;
		file_key2file_info_map[GetDataParameter(parameter_index_enum::FileObject)] = file_info;
		break;
	}
	case EM_FileioEventOPC::FileioCreateEvent:   //fileiocreate
	{
		std::wstring open_path = GetStringParameter(parameter_index_enum::OpenPath);
		if (GetDataParameter(parameter_index_enum::FileObject) == 0 || wcslen(open_path.c_str()) == 0)
			return 0;

		FileIoInfo file_info;
		file_info.file_name = open_path;
		file_info.used = 1;
		file_object2file_info_map[GetDataParameter(parameter_index_enum::FileObject)] = file_info;
		break;
	}
	case EM_FileioEventOPC::FileioClose:  //fileioclose
	{
		_ParseFileName();
		EventRecordPruner::GetInstance().OnFileIoClose(this);
		ULONG64 fileobject = GetDataParameter(parameter_index_enum::FileObject);
		ULONG64 filekey = GetDataParameter(parameter_index_enum::FileKey);
		file_object2file_info_map.erase(fileobject);
		file_key2file_info_map.erase(filekey);
		m_bUseless = true;
		break;
	}
	case EM_FileioEventOPC::FileioDirEnumerationEvent:
	//only filename,not file path,although it seems can be completed,when too many unkown file, we can think about to fix it.
	//Remaining work,and yet remove it from format.txt
	{
		std::wstring file_name = GetStringParameter(parameter_index_enum::FileName);
		if (wcscmp(L"*", file_name.c_str()) == 0 || wcslen(file_name.c_str()) == 0)
		{
			_ParseFileName();
			SetParameter(parameter_index_enum::FileName, _file_name);
		}

		SetParameter(parameter_index_enum::FileName, file_name);
		m_bUseless = true;						// add by zxw on 2019113 FileioDirEnumerationEvent is useless, only for ransom
		break;
	}
	case EM_FileioEventOPC::FileIoCleanup:	// add by zxw on 2019112 FileIoCleanup is useless, only for ransom
		m_bUseless = true;
		break;
	default:
		_ParseFileName();
		SetParameter(parameter_index_enum::FileName, _file_name);
		return 0;
	}

	return 0;
}

bool EventRecordFileio::Output()
{   
	//when fileiorename or FileIoRenamePath(opcode==80, only in win10),cache it 
	//when FileIoFileCreate, get filename after rename operation and return fileiorename event 
	bool flag = true;
	switch (this->get_event_identifier_().opcode())
	{
	case EM_FileioEventOPC::FileioRenameEvent:  //FileIoRename
	case EM_FileioEventOPC::FileIoRenamePath:  //FileIoRenamePath  (appear in WIN10)
	{
		((EventRecordFileio*)(this))->renameCache();
		//不需要del,原因是这个event会在FileioFileCreateEvent拿到并放入wait_send_dataqueue;
		return true;
	}
	case EM_FileioEventOPC::FileioFileCreateEvent:  //FileIoFileCreate  
	{
		//_TryProcessMacro();
       
		EventRecord* rename_event = ((EventRecordFileio*)(this))->renameCache();
		if (rename_event) 
		{
			rename_event->QPCtimeToSystime();
			//InitCollector::GetCollector()->PushSendRecord(rename_event);
			// add by zxw on 20191107 添加空指针保护
			if (InitCollector::GetCollector())
				InitCollector::GetCollector()->PushSendRecord(rename_event);
			else
			{
				EventRecordManager::GetInstance().RecycleEventRecord(rename_event);
				WriteLog4cPlus(ERROR_LEVEL, L"Output InitCollector::GetCollector is null ");
			}
		}

		//do not send FileIoFileCreate,delete and return 
		flag = false;
		break;
	}
	case EM_FileioEventOPC::FileioCreateEvent: 
	{        
		//do not send FileIoCreate,delete and return 
		//_TryProcessMacro();

		// mod by zxw on 20191128 ransom 模块需要先保留，output时再裁剪
        if (RansomCheck::getDetectFlag())
        {
            m_bUseless = true;
        }else
		    flag = false;
		
		break;
	}
	case EM_FileioEventOPC::FileIoRead:
	{
		//EventRecordPruner::GetInstance().CleanProcessCache(process_id_);
		if (!_force_convert_path && !EventRecordPruner::GetInstance().PrunFileIoReadWrite(this))
		{
			//flag = false;
			// mod by zxw on 20191128 ransom 模块需要先保留，output时再裁剪
            if (RansomCheck::getDetectFlag())
            {
                m_bUseless = true;
            }
            else
                flag = false;			
        }
       
		break;
	}
	case EM_FileioEventOPC::FileIoWirte:
	{
		if (!_force_convert_path && !EventRecordPruner::GetInstance().PrunFileIoReadWrite(this))
		{
			//flag = false;
			// mod by zxw on 20191128 ransom 模块需要先保留，output时再裁剪
            if (RansomCheck::getDetectFlag())
            {
                m_bUseless = true;
            }
            else
                flag = false;			
		}
		break;
    }
    case EM_FileioEventOPC::FileIoDelete:
    {
        if (!_force_convert_path && !EventRecordPruner::GetInstance().PrunFileIoDelete(this)) 
        {           
            // mod by zxw on 20191128 ransom 模块需要先保留，output时再裁剪
            if (RansomCheck::getDetectFlag()) {
                m_bUseless = true;
            }
            else
                flag = false;
        }
        break;
    }
	case EM_FileioEventOPC::FileioClose:
	{   
        // remove by zxw on 20200427 parse() already call it
		//EventRecordPruner::GetInstance().OnFileIoClose(this);
        flag = !m_bUseless;// add by zxw on 20200427 useless is true not output
		break;
	}
	default:
		flag = true;
		break;
	}

	if (flag)
	{
		QPCtimeToSystime();
        // add by zxw on 20210507
        if (!m_bUseless && get_event_identifier_().opcode() == EM_FileioEventOPC::FileIoWirte)
            AddIsDownloadParameter();

        // if enable_honey_pot start uploadfile
        //if (!useless && Setting::GetInstance().enable_honey_pot() && get_event_identifier_().opcode() == EM_FileioEventOPC::FileIoRead)
            //_UploadFile();

		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(this);
		return true;
	}

	return false;
}

void EventRecordFileio::_ParseFileName()
{
	if (GetDataParameter(parameter_index_enum::FileKey) != 0)
	{
		ULONG64 key = GetDataParameter(parameter_index_enum::FileKey);
		if (file_key2file_info_map.find(key) != file_key2file_info_map.end())
		{
			_file_name = file_key2file_info_map[key].file_name;
			file_key2file_info_map[key].used = 1;
		}
	}

	if (_file_name == L"" && GetDataParameter(parameter_index_enum::FileObject) != 0)
	{
		ULONG64 object_address = GetDataParameter(parameter_index_enum::FileObject);
		if (file_object2file_info_map.find(object_address) != file_object2file_info_map.end())
		{
			_file_name = file_object2file_info_map[object_address].file_name;
			file_object2file_info_map[object_address].used = 1;
		}

		if (wcslen(_file_name.c_str()) == 0)
		{
			if (file_context.find(object_address) != file_context.end())
			{
				_file_name = file_context[object_address];
			}
		}
	}

	if (wcslen(_file_name.c_str()) == 0)
	{
		m_bUseless = true;
	}
}

void EventRecordFileio::_TryProcessMacro()
{
	String process_file_name = Filter::GetInstance().GetProcessFileName(m_dwProcessId);
	if (process_file_name == EMPTY_STRING || !MacroDetector::GetInstance().IsMacroEnableApp(process_file_name))
	{
		return;
	}

	EventMacroResult* macro_event = new EventMacroResult(this);
	TaskQueueService::GetInstance().AddTask([=]()
	{
		macro_event->parse();
		if (macro_event->Output())
		{
			macro_event->QPCtimeToSystime();
			if (InitCollector::GetCollector())
				InitCollector::GetCollector()->PushSendRecord(macro_event);
		}
		else
		{
			delete macro_event;
		}
	});
}

void EventRecordFileio::_OnConvertPathError()
{
	if (InitCollector::GetCollector() && InitCollector::GetCollector()->GetMode() != EM_InitCollectorMode::ONLINE_PARSE_MODE)
	{
		return;
	}

	EventRecordFileio* clone = new EventRecordFileio();
	clone->InitFrom(this);
	clone->_force_convert_path = true;
	TaskQueueService::GetInstance().AddTask([clone]()
	{
		clone->InitParse();
		InitCollectorOnlineParse::PushSwitchEventRecord(clone);
	});
}

void EventRecordFileio::_UploadFile() 
{
    static std::unordered_set<std::wstring> file_name_set;
    // if file_name is null or is directory return
    if (_file_name.size() == 0 || ToolFunctions::isEndWith(_file_name.c_str(), L"\\"))
    {
        return;
    }

    if (file_name_set.find(_file_name) != file_name_set.end()) {
        return;
    }
    if (file_name_set.size() > 1000) {
        std::unordered_set<std::wstring>().swap(file_name_set);
    }
    file_name_set.insert(_file_name);

    static ULONG64 pruncounts, lastcountes;    
    pruncounts++;
    if (pruncounts % 10000 == 0 && lastcountes != pruncounts) {
        lastcountes = pruncounts;
        WriteLog4cPlus(INFO_LEVEL, L"EventRecordFileio::_UploadFile opencounts= %llu", pruncounts);
    }
#ifndef STANDALONE_COLLECTOR
    rapidjson::Document j_val;
    j_val.SetObject();
    rapidjson::Value value_t;
    value_t.SetString("UPLOAD_FILE", j_val.GetAllocator());
    j_val.AddMember("CMD", value_t, j_val.GetAllocator());

    value_t.SetString(ToolFunctions::WStringToString(_file_name).c_str(), j_val.GetAllocator());
    j_val.AddMember("filePath", value_t, j_val.GetAllocator());

    //QPCtimeToSystime();
    rapidjson::Value uint;
    uint.SetUint64(m_ulTimeStamp);
    j_val.AddMember("TimeStamp", uint, j_val.GetAllocator());

    NamedPipeClient::GetInstance().WritePipe(j_val);
#endif
}

void EventRecordFileio::AddIsDownloadParameter() 
{
    auto network_time = get_process_network_timestamp(m_dwProcessId);
    if (network_time > 0 && m_ulTimeStamp - network_time < NS_TEN_SECOND * 6)
    {
        SetParameter(parameter_index_enum::IsDownload, 1);
    }
    else {
        SetParameter(parameter_index_enum::IsDownload, 0);
    }
}

bool isOfficeFile(wstring file_path) 
{
	auto const pos = file_path.find_last_of('.');
	if (pos != std::string::npos)
	{
		wstring file_type = file_path.substr(pos + 1);
		transform(
			file_type.begin(), file_type.end(),
			file_type.begin(),
			tolower
		);
		for (wstring i : filetypes)
		{
			if (file_type == i)
			{
				return true;
			}
		}
	}
	return false;
}

bool isLoadByOffice(wstring process_name) 
{
	wstring  pname_lowercase = process_name;
	transform(
		pname_lowercase.begin(), pname_lowercase.end(),
		pname_lowercase.begin(),
		tolower
	);
	for (wstring pname : office_process) {
		if (pname_lowercase.find(pname) != wstring::npos) {
			return true;
		}
	}
	return false;
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordFileio 重命名缓存 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
EventRecord* EventRecordFileio::renameCache()
{
	int opcode = get_event_identifier_().opcode();
	switch (opcode) 
	{
	case EM_FileioEventOPC::FileioFileCreateEvent:
		{
			ULONG64 fileobject = GetDataParameter(parameter_index_enum::FileObject);
			if (fileiorename_cache_map.count(fileobject)) {
				EventRecord *rename_event = fileiorename_cache_map[fileobject];
				rename_event->SetParameter(parameter_index_enum::NewFileName, GetStringParameter(parameter_index_enum::FileName));
				fileiorename_cache_map.erase(fileobject);
				return rename_event;
			}
			else
				return NULL;
		}
		case EM_FileioEventOPC::FileioRenameEvent:
		case EM_FileioEventOPC::FileIoRenamePath:
		{
			ULONG64 filekey = GetDataParameter(parameter_index_enum::FileKey);
			// mod by zxw on 20191128 数据积压内存泄漏
			auto iter = fileiorename_cache_map.find(filekey);
			if (iter != fileiorename_cache_map.end())
			{
				EventRecord *rename_event = iter->second;
				EventRecordManager::GetInstance().RecycleEventRecord(rename_event);
				iter->second = this;				
			}
			else
			{
				fileiorename_cache_map.insert(make_pair(filekey, this));
			}			
			//fileiorename_cache_map[filekey] = this;
			return NULL;
		}
	}
	return NULL;
}

EventRecordTcpip::EventRecordTcpip(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordTcpip);
}

EventRecordTcpip::EventRecordTcpip()
{
    OBJECT_MEMORY_MONITOR_CTOR(EventRecordTcpip);
}

EventRecordTcpip::~EventRecordTcpip()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordTcpip);
}

void EventRecordTcpip::InitParse()
{
	m_dwProcessId = GetDataParameter(parameter_index_enum::PID);
	m_dwThreadId = m_umapProcessTcpPreEventrecord[m_dwProcessId];
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordTcpip
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum， 现在这个函数暂时用不到 所以不会进入 考虑到以后可能会继续使用 不做删除
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */

int EventRecordTcpip::parse()
{
	return 0;
}

bool EventRecordTcpip::Output()
{
    /* mod by zxw on 20191230 change prun network method one min only send one event
	EM_TcpIpEventOPC opcode = (EM_TcpIpEventOPC)event_identifier_.opcode();
	switch (opcode)
	{
	case EM_TcpIpEventOPC::TcpIpSendIPV4:
		if (!EventRecordPruner::GetInstance().PrunTcpIpSend(this))	return false;
		break;
	case EM_TcpIpEventOPC::TcpIpRecvIPV4:
		EventRecordPruner::GetInstance().CleanProcessCache(GetDataParameter(parameter_index_enum::PID));
		if (!EventRecordPruner::GetInstance().PrunTcpIpRecv(this))	return false;
		break;
	}
    */
	QPCtimeToSystime();

    EM_TcpIpEventOPC opcode = (EM_TcpIpEventOPC)m_eventIdentifier.opcode();
    if (opcode == EM_TcpIpEventOPC::TcpIpSendIPV4 || opcode == EM_TcpIpEventOPC::TcpIpRecvIPV4)
    {
        // add by zxw on 20210507
        update_process_id2network_time_map_(m_dwProcessId, m_ulTimeStamp);

        if (!EventRecordPruner::GetInstance().PrunTcpIpEvent(this))	
            return false;
        if (!EventRecord::query_process_id2process_name_map_(m_dwProcessId))
        {
            //WriteLog4cPlus(WARN_LEVEL, L"EventRecordTcpip::Output: process is not start or already end ignore event, pid %d", m_dwProcessId);
            return false;
        }         
    }    

	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);
	return true;
}

EventRecordUdpip::EventRecordUdpip(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordUdpip);
}

EventRecordUdpip::EventRecordUdpip()
{
    OBJECT_MEMORY_MONITOR_CTOR(EventRecordUdpip);
}

EventRecordUdpip::~EventRecordUdpip()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordUdpip);
}

void EventRecordUdpip::InitParse()
{
	m_dwThreadId = 0;
	m_dwProcessId = GetDataParameter(parameter_index_enum::PID);
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordUdpip 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    增加注释
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */

int EventRecordUdpip::parse()
{
	return 0;
}

bool EventRecordUdpip::Output()
{
    /* mod by zxw on 20191230 change prun network method one min only send one event
	EM_TcpIpEventOPC opcode = (EM_TcpIpEventOPC)event_identifier_.opcode();
	switch (opcode)
	{
	case EM_TcpIpEventOPC::TcpIpSendIPV4:
		if (!EventRecordPruner::GetInstance().PrunUdpIpSend(this))	return false;
		break;
	case EM_TcpIpEventOPC::TcpIpRecvIPV4:
		EventRecordPruner::GetInstance().CleanProcessCache(GetDataParameter(parameter_index_enum::PID));
		if (!EventRecordPruner::GetInstance().PrunUdpIpRecv(this))	return false;
		break;
	}
    */

    QPCtimeToSystime();

    EM_UdpIpEventOPC opcode = (EM_UdpIpEventOPC)m_eventIdentifier.opcode();
    if (opcode == EM_UdpIpEventOPC::UdpIpSendIPV4 || opcode == EM_UdpIpEventOPC::UdpIpRecvIPV4)
    {    
        // add by zxw on 20210507
        update_process_id2network_time_map_(m_dwProcessId, m_ulTimeStamp);

        if (!EventRecordPruner::GetInstance().PrunUdpIpEvent(this)) 
            return false;
        if (!EventRecord::query_process_id2process_name_map_(m_dwProcessId)) {
            //WriteLog4cPlus(WARN_LEVEL, L"EventRecordUdpip::Output: process is not start or already end ignore event, pid %d", m_dwProcessId);
            return false;
        }       
    }
   
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);
	return true;
}

EventRecordDiskio::EventRecordDiskio(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordDiskio);
}

EventRecordDiskio::~EventRecordDiskio()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordDiskio);
}

void EventRecordDiskio::InitParse()
{
	if (m_dwThreadId == -1)
	{
		if (GetDataParameter(parameter_index_enum::TTID) != 0)
		{
			m_dwThreadId = GetDataParameter(parameter_index_enum::TTID);
		}
		else
		{
			if (m_nProcessorId >= 0 && m_nProcessorId <= 64)   // a tricky design,
			{
				m_dwThreadId = m_vctProcessorId2TidList[m_nProcessorId];
			}
		}
		auto ix = m_umapTid2Pid.find(m_dwThreadId);
		m_dwProcessId = ix != m_umapTid2Pid.end() ? ix->second : -1;
	}
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordDiskio 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    增加注释
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordDiskio::parse()
{
	return 0;
}

EventRecordPerfInfo::EventRecordPerfInfo(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordPerfInfo);
}

EventRecordPerfInfo::~EventRecordPerfInfo()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordPerfInfo);
}

void EventRecordPerfInfo::InitParse()
{
	if (m_nProcessorId >= m_vctProcessorId2TidList.size())
	{
		m_dwThreadId = 0;
		m_dwProcessId = 0;
		m_bUseless = true;
	}
	else
	{
		m_dwThreadId = m_vctProcessorId2TidList[m_nProcessorId];
		auto ix = m_umapTid2Pid.find(m_dwThreadId);
		m_dwProcessId = ix != m_umapTid2Pid.end() ? ix->second : -1;
	}
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordPerfInfo 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    增加注释
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordPerfInfo::parse()
{
	switch (m_eventIdentifier.opcode())
	{
	case EM_PerfInfoEventOPC::SyscallEnter:
	{
		DWORD address = GetDataParameter(parameter_index_enum::SysCallAddress);
		String syscall_api = SystemCallDetector::GetInstance().ParseApi(address);
		SetParameter(parameter_index_enum::SystemCall, ToolFunctions::StringToWString(syscall_api));
		if (syscall_api.empty())	m_bUseless = true;
       
		//Pruning system call
		if (syscall_api == "NtUserGetKeyState" || syscall_api == "NtUserGetKeyboardState"
			|| syscall_api == "NtUserGetAsyncKeyState") 
		{
			//if (PhfDetector::keylogger_process_cache.count(process_id_))
            if (PhfDetector::m_setKeyloggerThreadCache.count(m_dwThreadId))
				m_bUseless = true;
		}
       
		break;
	}
		
	default:
		m_bUseless = true;
		break;
	}
	
	return 0;
}

bool EventRecordPerfInfo::Output()
{
	QPCtimeToSystime();

	if (Setting::GetInstance().local_detector_parse())
	{
		PhfDetector::GetInstance().TryDetectPhf();
		PhfDetector::GetInstance().ProcessSystemCall(this);
		return false;
	}
	else {
		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(this);
	}

	return true;
}

EventRecordAlpc::EventRecordAlpc(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordAlpc);
}

EventRecordAlpc::EventRecordAlpc(DWORD input_thread_id, DWORD input_process_id, ULONG64 time_stamp)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordAlpc);

	m_dwProcessId = input_process_id;
	m_dwThreadId = input_thread_id;
	m_eventIdentifier = EventIdentifier(ETWALPC, EM_AlpcEventOPC::AlpcSendEvent);
	m_bUseless = false;
	m_ulTimeStamp = time_stamp;
}

EventRecordAlpc::~EventRecordAlpc()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordAlpc);
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordAlpc 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
int EventRecordAlpc::parse()
{
	int event_opcode = m_eventIdentifier.opcode();


	if (event_opcode == EM_AlpcEventOPC::AlpcSendEvent)
	{
		AlpcMessage alpc_message_send;
		alpc_message_send.message_id = GetDataParameter(parameter_index_enum::MessageID);
		alpc_message_send.process_id = m_dwProcessId;
		alpc_message_send.thread_id = m_dwThreadId;
		send_message_list_.push_back(alpc_message_send);
		SetParameter(parameter_index_enum::ProcessId, 0);
		SetParameter(parameter_index_enum::TThreadId, 0);
		SetParameter(parameter_index_enum::ProcessName, L"N");

	}
	else
		if (event_opcode == EM_AlpcEventOPC::ApcReceiveEvent)
		{
			std::list<AlpcMessage>::iterator i_alpc_message = find_if(send_message_list_.begin(), send_message_list_.end(), messageid_to_find(GetDataParameter(parameter_index_enum::MessageID)));
			if (i_alpc_message == send_message_list_.end())
			{
				m_bUseless = true;
				return 0;
			}
			SetParameter(parameter_index_enum::ProcessId, i_alpc_message->process_id);
			SetParameter(parameter_index_enum::TThreadId, i_alpc_message->thread_id);
			std::unordered_map<DWORD, std::wstring>::iterator ix = m_umapPid2ProcessName.find(i_alpc_message->process_id);
			if (ix != m_umapPid2ProcessName.end())
				SetParameter(parameter_index_enum::ProcessName, ix->second);
			else m_bUseless = TRUE;
			send_message_list_.erase(i_alpc_message);
		}
	return 0;
}

STRING_SET EventRecordImage::_dll_need_rva_set =
{
	"\\SysWOW64\\KernelBase.dll",
	"\\SysWOW64\\mswsock.dll",
	"\\SysWOW64\\wininet.dll",
	"\\SysWOW64\\BCP47Langs.dll",
	"\\System32\\ntmarta.dll",
	"\\SysWOW64\\advapi32.dll",
	"\\System32\\wow64.dll",
	"\\SysWOW64\\kernel32.dll",
	"\\SysWOW64\\shell32.dll",
	"\\System32\\ntdll.dll",
	"\\System32\\gdi32.dll",
	"\\SysWOW64\\CoreMessaging.dll",
	"\\SysWOW64\\SHCore.dll",
	"\\System32\\user32.dll",
	"\\SysWOW64\\ntmarta.dll",
	"\\SysWOW64\\rsaenh.dll",
	"\\SysWOW64\\ieframe.dll",
	"\\SysWOW64\\apphelp.dll",
	"\\SysWOW64\\urlmon.dll",
	"\\System32\\ole32.dll",
	"\\SysWOW64\\Windows.StateRepositoryCore.dll",
	"\\System32\\AppXDeploymentClient.dll",
	"\\SysWOW64\\BCP47mrm.dll",
	"\\SysWOW64\\winmmbase.dll",
	"\\System32\\imm32.dll",
	"\\System32\\cryptsp.dll",
	"\\SysWOW64\\GdiPlus.dll",
	"\\System32\\winmm.dll",
	"\\System32\\rpcrt4.dll",
	"\\System32\\ucrtbase.dll",
	"\\SysWOW64\\combase.dll",
	"\\SysWOW64\\imm32.dll",
	"\\SysWOW64\\edputil.dll",
	"\\System32\\SHCore.dll",
	"\\System32\\BCP47mrm.dll",
	"\\SysWOW64\\gdi32.dll",
	"\\System32\\win32u.dll",
	"\\System32\\wininet.dll",
	"\\System32\\bcrypt.dll",
	"\\SysWOW64\\mscoree.dll",
	"\\SysWOW64\\ws2_32.dll",
	"\\System32\\KernelBase.dll",
	"\\System32\\Windows.UI.dll",
	"\\System32\\mscoree.dll",
	"\\SysWOW64\\bcrypt.dll",
	"\\System32\\gdi32full.dll",
	"\\SysWOW64\\WindowsCodecs.dll",
	"\\System32\\Windows.StateRepositoryCore.dll",
	"\\System32\\advapi32.dll",
	"\\SysWOW64\\wsock32.dll",
	"\\System32\\comctl32.dll",
	"\\SysWOW64\\propsys.dll",
	"\\System32\\CoreMessaging.dll",
	"\\SysWOW64\\msvcrt.dll",
	"\\System32\\MrmCoreR.dll",
	"\\System32\\mswsock.dll",
	"\\SysWOW64\\gdi32full.dll",
	"\\SysWOW64\\winmm.dll",
	"\\System32\\nsi.dll",
	"\\System32\\winmmbase.dll",
	"\\System32\\WindowsCodecs.dll",
	"\\SysWOW64\\MrmCoreR.dll",
	"\\SysWOW64\\drvstore.dll",
	"\\System32\\uxtheme.dll",
	"\\System32\\ws2_32.dll",
	"\\SysWOW64\\wow64cpu.dll",
	"\\System32\\shell32.dll",
	"\\System32\\windows.storage.dll",
	"\\System32\\kernel32.dll",
	"\\SysWOW64\\nsi.dll",
	"\\SysWOW64\\devrtl.dll",
	"\\SysWOW64\\comctl32.dll",
	"\\SysWOW64\\ucrtbase.dll",
	"\\System32\\propsys.dll",
	"\\SysWOW64\\wow64.dll",
	"\\System32\\apphelp.dll",
	"\\System32\\urlmon.dll",
	"\\SysWOW64\\ntdll.dll",
	"\\System32\\devrtl.dll",
	"\\System32\\edputil.dll",
	"\\System32\\wow64cpu.dll",
	"\\SysWOW64\\win32u.dll",
	"\\System32\\GdiPlus.dll",
	"\\SysWOW64\\Windows.UI.dll",
	"\\SysWOW64\\windows.storage.dll",
	"\\SysWOW64\\uxtheme.dll",
	"\\SysWOW64\\rpcrt4.dll",
	"\\System32\\xmllite.dll",
	"\\System32\\combase.dll",
	"\\SysWOW64\\cryptsp.dll",
	"\\System32\\rsaenh.dll",
	"\\System32\\wsock32.dll",
	"\\SysWOW64\\xmllite.dll",
	"\\System32\\ieframe.dll",
	"\\SysWOW64\\user32.dll",
	"\\System32\\drvstore.dll",
	"\\System32\\BCP47Langs.dll",
	"\\SysWOW64\\shlwapi.dll",
	"\\SysWOW64\\lsasrv.dll",
	"\\System32\\msvcrt.dll",
	"\\System32\\shlwapi.dll",
	"\\System32\\lsasrv.dll",
	"\\SysWOW64\\ole32.dll",
	"\\SysWOW64\\AppXDeploymentClient.dll",
};

STRING_SET EventRecordImage::_dll_need_rva_ransom_set =
{	
	"\\system32\\advapi32.dll",
	"\\syswow64\\advapi32.dll",
	"\\system32\\crypt32.dll",
	"\\syswow64\\crypt32.dll",
	"\\system32\\cryptsp.dll",  
	"\\syswow64\\cryptsp.dll",  
	"\\system32\\rpcrt4.dll",
	"\\syswow64\\rpcrt4.dll",
	"\\system32\\wininet.dll",
	"\\syswow64\\wininet.dll",
	"\\system32\\ws2_32.dll",
	"\\syswow64\\ws2_32.dll",
	"\\system32\\kernel32.dll",
	"\\syswow64\\kernel32.dll",
	"\\system32\\ntdll.dll",
	"\\syswow64\\ntdll.dll",
	"\\syswow64\\user32.dll",
	"\\syswow64\\user32.dll",
};


// previous api used by the model
/*
{
	K32GetProcessImageFileName  Psapi.dll(discard, for it only contain one associated api)
	CryptImportKey			    Advapi32.dll
	CryptDecrypt				Advapi32.dll
}
*/

// may only used in ransomware
/*
{		
	InternetOpen				Wininet.dll
	CryptDeriveKey				Advapi32.dll
	CryptDecodeObject			Crypt32.dll
	CryptGenKey					Advapi32.dll
	CryptImportPublicKeyInfo	Crypt32.dll
	GetUserName					Advapi32.dll
	NdrClientCall2				Rpcrt4.dll
	Socket						Ws2_32.dll
}
*/

// have not added to the list 202302
// higher frequency used in ransomware than common process
/*{
	CoCreateInstance			Ole32.dll
	GetFileType					Kernel32.dll
}*/

// have not added to the list 202302
// a little higher frequency used in ransomware than common process
/*
{
	CryptAcquireContext			Advapi32.dll
	CloseHandle					Kernel32.dll
	FindNextFile				Kernel32.dll
	SetFilePointer				Kernel32.dll
	GetFileSize					Kernel32.dll
	SetFileAttributes			Kernel32.dll
}
*/

void EventRecordImage::InitFrom(EventRecord* origin)
{
	EventRecord::InitFrom(origin);
	_force_convert_path = dynamic_cast<EventRecordImage*>(origin)->_force_convert_path;
}

void EventRecordImage::InitParse()
{
	m_dwProcessId = GetDataParameter(parameter_index_enum::ProcessId);
	std::wstring module_name = GetStringParameter(parameter_index_enum::FileName);
	if (ToolFunctions::isEndWith(module_name.c_str(), L"exe") 
		|| ToolFunctions::isEndWith(module_name.c_str(), L"EXE"))
	{
		m_bNeedRva = true;
		_force_convert_path = true;
	}
	else
	{
		String module_name_t = ToolFunctions::WStringToString(module_name);
		size_t find_pos = module_name_t.find("\\Windows");
		size_t offset = 8;
		if (find_pos == String::npos)
		{
			find_pos = module_name_t.find("\\SystemRoot");
			offset = 11;
		}
		if (find_pos != String::npos)
		{
			find_pos += offset;
			module_name_t = module_name_t.substr(find_pos, module_name_t.size() - find_pos);
			// 目前 phf的API和ransomware的API，二选一解析，且优先ransomware
			if (RansomCheck::getDetectFlag())
			{
				transform(module_name_t.begin(), module_name_t.end(), module_name_t.begin(), ::tolower);
				if (_dll_need_rva_ransom_set.find(module_name_t) != _dll_need_rva_ransom_set.end()
					|| module_name_t.find("gdiplus.dll") != String::npos)
					m_bNeedRva = true;
			}
			else 
				m_bNeedRva = _dll_need_rva_set.find(module_name_t) != _dll_need_rva_set.end() 
				|| module_name_t.find("gdiplus.dll") != String::npos;
		}
	}

	if (m_bNeedRva)
	{
		std::wstring converted_file_path;
		_convert_path_succ = ObtainEntryAddress::m_drivemap.ConvertDeviceFormat2DriveFormat(module_name, converted_file_path, _force_convert_path);
		if (!_convert_path_succ && !_force_convert_path)
		{
			_OnConvertPathError();
		}
		SetParameter(parameter_index_enum::FileName, converted_file_path);
	}
	else
	{
		_convert_path_succ = true;
	}

	SetParameter(parameter_index_enum::IsMainModule, 0);
}

bool EventRecordImage::is_ransom_black(const std::wstring& module_name) const
{
	auto module = StringUtil::ToLowerCase(module_name);
	if (StringUtil::IsStartWith(module, L"c:\\windows\\", false))
	{
		for (auto&& path : vec_black_list_ransom)
		{
			if (StringUtil::IsEndWith(module, path, false)) return true;
		}
	}
	return false;
}

/**
 *  @date       2018/12/28
 *  @brief      解析EventRecordImage 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    修改把数字改enum
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */

int EventRecordImage::parse()
{
	// handle imageload and dcstart event, read in dll rva
	if (m_eventIdentifier.opcode() == EM_ImageEventOPC::ImageDCStart 
		|| m_eventIdentifier.opcode() == EM_ImageEventOPC::ImageLoad)
	{
		EventRecordPruner::GetInstance().CleanProcessCache(m_dwProcessId);

		// attentation here, the process id of ImageDCstart is ETWCollector's process id
		if (!ObtainEntryAddress::m_moduleAddressTree[m_dwProcessId % Max_Process_ID]) 
			ObtainEntryAddress::m_moduleAddressTree[m_dwProcessId % Max_Process_ID] = new btree();
		if (m_cRunningModeFlag == ONLINE_PARSE_MODE_STR 
			&& m_dwProcessId == GetCurrentProcessId())
			return 0;

		// do not certificate it immediately, set 2 means wait certificate result 
		SetParameter(parameter_index_enum::Certificate, 2);
		
		std::wstring module_name = GetStringParameter(parameter_index_enum::FileName);
		// for callstack pruning!DE
		if (ToolFunctions::isEndWith(module_name.c_str(), L"exe") 
			|| ToolFunctions::isEndWith(module_name.c_str(), L"EXE") 
			|| ToolFunctions::IsExecutableFile(module_name))
		{
			Filter::AddFullPath(m_dwProcessId, module_name);
			process_map::g_umapPid2ProcessInfo[m_dwProcessId].process_path = module_name;
			if (is_ransom_black(module_name))
			{
				RansomCheck::addRansomBlackList(m_dwProcessId);
			}
			if (ObtainEntryAddress::m_umapExeNode.find(m_dwProcessId) == ObtainEntryAddress::m_umapExeNode.end())
			{
#ifndef STANDALONE_COLLECTOR
				std::map<DWORD, ProcessInfoItem>::iterator it;
				it = ProcessInfo::process_info.find(m_dwProcessId);
				if (it != ProcessInfo::process_info.end())
				{
					it->second.file_path_ = module_name;
					NamedPipeClient::GetInstance().WritePipe(it->second);
					ProcessInfo::process_info.erase(it);
				}
#endif
				ExeModuleAddress tmpAddress;
				tmpAddress.image_base_ = GetDataParameter(parameter_index_enum::ImageBase);
				tmpAddress.image_end_ = tmpAddress.image_base_ + GetDataParameter(parameter_index_enum::ImageSize);
				CallstackPruning::m_umapProcessid2Exemoduleaddress[m_dwProcessId] = tmpAddress;
				dllAddress tmpdllAddress;
				tmpdllAddress.FileName = ToolFunctions::WStringToString(ToolFunctions::DeleteDriverName(module_name));
				tmpdllAddress.ImageBase = tmpAddress.image_base_;
				tmpdllAddress.ImageEnd = tmpAddress.image_end_;
				tmpdllAddress.rva_tree = NULL;
				if (_convert_path_succ)
				{
					ObtainEntryAddress::m_moduleAddressTree[m_dwProcessId % Max_Process_ID]->insert(tmpdllAddress);
					ObtainEntryAddress::m_umapExeNode[m_dwProcessId] = tmpdllAddress;
				}

				if (RansomCheck::getDetectFlag())
				{
					Filter::insert_registry_pid_white_list(m_dwProcessId, module_name);
				}

				Filter::GetInstance().OnExeImageLoad(m_dwProcessId, tmpdllAddress.FileName);
				SetParameter(parameter_index_enum::IsMainModule, 1);
				return 0;
			}
		}
		// leave ".sys" module out for now
		else if ((!ToolFunctions::isEndWith((module_name).c_str(), L".dll")) 
			&& (!ToolFunctions::isEndWith((module_name).c_str(), L".DLL")))
			return 0;

		dllAddress tmpAddress;
		tmpAddress.FileName = ToolFunctions::WStringToString(ToolFunctions::DeleteDriverName(module_name));
		tmpAddress.ImageSize = GetDataParameter(parameter_index_enum::ImageSize);
		tmpAddress.ImageBase = GetDataParameter(parameter_index_enum::ImageBase);
		tmpAddress.ImageEnd = tmpAddress.ImageBase + tmpAddress.ImageSize;
		tmpAddress.rva_tree = NULL;

		if (tmpAddress.ImageSize == 0)
		{
			WriteLog4cPlus(ERROR_LEVEL, L"EventRecordImage::parse: ImageSize = 0");
			return 0;
		}

		// in realtime mode, we get the rva tree from the dll directly
		// TODO win7 winsxs win10 WinSxs
		if (m_cRunningModeFlag == ONLINE_PARSE_MODE_STR)
		{
			ObtainEntryAddress::m_ulCurrentModuleSize = tmpAddress.ImageSize;
			if (module_name.find(L"\\Windows\\System32") == std::wstring::npos &&
				module_name.find(L"\\Windows\\SysWOW64") == std::wstring::npos &&
				module_name.find(L"\\Windows\\WinSxS") == std::wstring::npos &&
				module_name.find(L"\\Windows\\winsxs") == std::wstring::npos)
				return 0;
			else
			{
				if (m_bNeedRva)
				{
					// statistic the mount of the dll
					DllUnit::increase(m_dwProcessId, tmpAddress.FileName);
					tmpAddress.rva_tree = ObtainEntryAddress::getModuleRvaFromFileName(module_name);
				}
			}
		}
		else if (m_cRunningModeFlag == OFFLINE_PARSE_MODE_STR)
		{
			transform(module_name.begin(), module_name.end(), module_name.begin(), ::tolower);
			if (ObtainEntryAddress::m_umapDLLmodual2Tree.count(module_name) != 0)
			{
				tmpAddress.rva_tree = &(ObtainEntryAddress::m_umapDLLmodual2Tree[module_name]);
			}
		}
		else
		{

		}

		if (_convert_path_succ)
		{
			ObtainEntryAddress::m_moduleAddressTree[m_dwProcessId % Max_Process_ID]->insert(tmpAddress);
		}

		if (ToolFunctions::isEndWith((module_name).c_str(), L"jvm.dll") 
			|| module_name.find(L"Windows\\Microsoft.NET\\Framework") != string::npos) 
		{
			//ObtainEntryAddress::moduleAddressTree[process_id_].head_of_tree()->key_value.Verification = false;
		}
	}
	else if (m_eventIdentifier.opcode() == EM_ImageEventOPC::ImageUnload)
	{
		if (m_cRunningModeFlag == ONLINE_PARSE_MODE_STR && m_dwProcessId == GetCurrentProcessId())
		{
			return 0;
		}

		const std::wstring& module_name = GetStringParameter(parameter_index_enum::FileName);
		if (ToolFunctions::isEndWith(module_name.c_str(), L"exe") || ToolFunctions::isEndWith(module_name.c_str(), L"EXE") || ToolFunctions::IsExecutableFile(module_name))
		{
			RansomCheck::removeRansomBlackList(m_dwProcessId);
			auto iter_f = ObtainEntryAddress::m_umapExeNode.find(m_dwProcessId);
			if (iter_f != ObtainEntryAddress::m_umapExeNode.end() && iter_f->second.ImageBase == GetDataParameter(parameter_index_enum::ImageBase))
			{
				ObtainEntryAddress::m_umapExeNode.erase(m_dwProcessId);
				CallstackPruning::m_umapProcessid2Exemoduleaddress.erase(m_dwProcessId);
			}
		}
		else if (ToolFunctions::isEndWith((module_name).c_str(), L".dll") 
			|| ToolFunctions::isEndWith((module_name).c_str(), L".DLL"))
		{
			
			btree* address_tree = ObtainEntryAddress::m_moduleAddressTree[m_dwProcessId % Max_Process_ID];
			if (address_tree != nullptr)
			{
				dllAddress dll_address;
				dll_address.FileName = ToolFunctions::WStringToString(ToolFunctions::DeleteDriverName(module_name));
				if (RansomCheck::getDetectFlag())
				{
					EventRecordCallstack::UnCacheRansomAPI(dll_address.FileName);
				}
				dll_address.ImageSize = GetDataParameter(parameter_index_enum::ImageSize);
				dll_address.ImageBase = GetDataParameter(parameter_index_enum::ImageBase);
				dll_address.ImageEnd = dll_address.ImageBase + dll_address.ImageSize;
				dll_address.rva_tree = NULL;
				address_tree->erase(dll_address);
			}
		}
	}
//#ifdef ETW_EVENT_RECORD_TEST
//	this->Record2csv("EventRecordImage_parse");
//#endif // ETW_EVENT_RECORD_TEST	
	return 0;
}

bool EventRecordImage::Output()
{
	EM_ImageEventOPC op_code = (EM_ImageEventOPC)get_event_identifier_().opcode();
	if (op_code == EM_ImageEventOPC::ImageUnload)
	{
		return false;
	}

	QPCtimeToSystime();

	if (op_code == EM_ImageEventOPC::ImageDCStart || op_code == EM_ImageEventOPC::ImageLoad)
	{
		const std::wstring& file_path = GetStringParameter(parameter_index_enum::FileName);
		if (ToolFunctions::isEndWith(file_path.c_str(), L".dll") || ToolFunctions::isEndWith(file_path.c_str(), L".DLL"))
		{
			return false;
		}

        EventRecord* temp = new EventRecordImage;
        copy(temp);
        if (ThreadTaskManager::GetInstance().AddEventRecord(CERTIFICATE_IMAGE_TASK_MODE, temp) == false) {
            delete temp;
        }

        // add by zxw on 20201027
        if (ToolFunctions::isEndWith(file_path.c_str(), L"exe") || ToolFunctions::isEndWith(file_path.c_str(), L"EXE"))
        {
            auto isMainMod = GetDataParameter(parameter_index_enum::IsMainModule);
            if (isMainMod == 1)
            {
                EventRecord* hash_temp = new EventRecordImage;
                copy(hash_temp);

                if (ThreadTaskManager::GetInstance().AddEventRecord(GEE_HASH_TASK_MODE, hash_temp) == false) {
                    delete hash_temp;
                }
            }         
        }       
	}
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);

//#ifdef ETW_HASH_TEST
//	this->Record2csv("EventRecordImage_Output");
//#endif // ETW_HASH_TEST
	return true;
}

/**
 *  @date       2018/12/28
 *  @brief      解析certificate 事件
 *  @param[in]  无
 *  @param[out] 无
 *  @return		int 0 暂时无意义
 *  @pre
 *  @remarks    增加注释
 *  @see
 *  @author		jiehao.meng
 *  @version	1.0.0.1
 */
void EventRecordImage::certificate()
{
	const std::wstring& file_name = GetStringParameter(parameter_index_enum::FileName);
    EM_CertificateResult result = CertificateTool::VerifyEmbeddedSignature(file_name.c_str());
	SetParameter(parameter_index_enum::Certificate, result);

	if (ToolFunctions::isEndWith(file_name.c_str(), L"exe") || ToolFunctions::isEndWith(file_name.c_str(), L"EXE"))
	{
		Filter::GetInstance().OnExeCertificateResult(m_dwProcessId, result);
	}
    // add by zxw on 20201013
    const std::wstring zone_name = file_name + L":Zone.Identifier";
    int zoneID = 0;
    std::wstring ReferrerUrl,HostUrl;
    if (ZoneIdentifier::GetZoneTransfer(zone_name.c_str(), zoneID, ReferrerUrl, HostUrl))
    {        
        EventRecord* event_record = EventRecordManager::GetInstance().ParseZoneIdentifierEvent(m_ulTimeStamp, m_dwProcessId, zoneID, ReferrerUrl, HostUrl, file_name);
        InitCollector::GetCollector()->PushSendRecord(event_record);
    }
    //
    // add by zxw on 20210510
	// the white list of the certificate has not been used, and the method consumes a lot of CPU resources
	// remove it
	/*
    if (result == CERTIFICATE_RESULT__NORMAL)
    {
        std::wstring    CataFile;
        std::string     SignType;
        std::list<SIGN_NODE_INFO> SignChain;

        BOOL bReturn = CheckFileDigitalSignature(file_name.c_str(), NULL, CataFile, SignType, SignChain);
        if (bReturn)
        {
            CheckCertificate(SignChain);
        }
    }
	*/
}

void EventRecordImage::CheckCertificate(std::list<SIGN_NODE_INFO> SignChain) 
{
    auto it = SignChain.begin();
    while (it != SignChain.end())
    {
        for (auto var: it->CertChain)
        {
            if (Filter::GetInstance().IsInCertificateWhiteList(var.Thumbprint, var.SubjectName))
            {
                Filter::GetInstance().AddSurpCertificateWhiteListBuffer(m_dwProcessId);
                return;
            }
        }
        it++;
    }
}



void EventRecordImage::_OnConvertPathError()
{
	if (InitCollector::GetCollector()->GetMode() != EM_InitCollectorMode::ONLINE_PARSE_MODE)
	{
		return;
	}
	
	EventRecordImage* clone = new EventRecordImage();
	clone->InitFrom(this);
	clone->_force_convert_path = true;
	TaskQueueService::GetInstance().AddTask([clone]()
	{
		clone->InitParse();
		InitCollectorOnlineParse::PushSwitchEventRecord(clone);
	});
}

EventRecordImage::EventRecordImage()
	: _force_convert_path(false)
	, _convert_path_succ(false)
	, m_bNeedRva(false)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordImage);
}

EventRecordImage::EventRecordImage(PEVENT_RECORD raw_rec)
	: EventRecord(raw_rec)
	, _force_convert_path(false)
	, _convert_path_succ(false)
	, m_bNeedRva(false)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordImage);
}

EventRecordImage::~EventRecordImage()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordImage);
}

EventRecordUnknown::EventRecordUnknown()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordUnknown);
}

EventRecordUnknown::~EventRecordUnknown()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordUnknown);
}

/**
*  @date       2018/12/28
*  @brief      解析certificate 事件
*  Generate a new alpc send record, when an alpc message is recieved.
*  Because only at this time, we can know which process this message is sent to.
*  This function should be called when consume a valid alpc receive event.
*  @param[in]  无
*  @param[out] 无
*  @return		int 0 暂时无意义
*  @pre
*  @remarks    增加注释
*  @see
*  @author		jiehao.meng
*  @version	1.0.0.1
*/
EventRecord* EventRecordAlpc::get_correspond_send()
{
	DWORD sender_thread_id = GetDataParameter(parameter_index_enum::TThreadId);
	DWORD sender_process_id = GetDataParameter(parameter_index_enum::ProcessId);
	DWORD message_id = GetDataParameter(parameter_index_enum::MessageID);
	ULONG64 timestamp = m_ulTimeStamp;

	EventRecordAlpc* sender = new EventRecordAlpc(sender_thread_id, sender_process_id, timestamp);

	sender->SetParameter(parameter_index_enum::MessageID, message_id);
	sender->SetParameter(parameter_index_enum::ProcessId, m_dwProcessId);
	sender->SetParameter(parameter_index_enum::TThreadId, m_dwThreadId);
	auto it = m_umapPid2ProcessName.find(m_dwProcessId);
	if (it != m_umapPid2ProcessName.end())
		sender->SetParameter(parameter_index_enum::ProcessName, m_umapPid2ProcessName[m_dwProcessId]);
	else
		sender->m_bUseless = true;

	return sender;
}
/*
image load
*/

EventRecordVisibleWindow::EventRecordVisibleWindow()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordVisibleWindow);
}

EventRecordVisibleWindow::~EventRecordVisibleWindow()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordVisibleWindow);
}

EventRecordMouse::EventRecordMouse()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordMouse);
}

EventRecordMouse::~EventRecordMouse()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordMouse);
}

EventRecordKeyBoard::EventRecordKeyBoard()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordKeyBoard);
}

EventRecordKeyBoard::~EventRecordKeyBoard()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordKeyBoard);
}

EventMacroResult::EventMacroResult(EventRecordFileio* rec_file_io)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventMacroResult);

	m_ulTimeStamp = rec_file_io->get_time_stamp_();
	m_dwProcessId = rec_file_io->get_process_id_();
	m_dwThreadId = rec_file_io->get_thread_id_();
	m_eventIdentifier = EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::FileMacroCheck);

	_original_opcode = (EM_FileioEventOPC)rec_file_io->get_event_identifier_().opcode();
	_original_pname = m_umapPid2ProcessName[(DWORD)m_dwProcessId];

	_result = EM_MarcoDetectResult::NORMAL;
	switch (_original_opcode)
	{
	case EM_FileioEventOPC::FileioNameEvent:
	case EM_FileioEventOPC::FileioFileCreateEvent:
	case EM_FileioEventOPC::FileIoWirte:
		_file_path = rec_file_io->GetStringParameter(parameter_index_enum::FileName);
		break;
	case EM_FileioEventOPC::FileioCreateEvent:
		_file_path = rec_file_io->GetStringParameter(parameter_index_enum::OpenPath);
		break;
	}
}

EventMacroResult::~EventMacroResult()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventMacroResult);
}

int EventMacroResult::parse()
{
	++_parse_counter;
	if (_parse_counter % 20000 == 0)
	{
		unordered_map<std::wstring, int_32>().swap(_detected_macro_file_record_map);
		_parse_counter = 0;
	}

	wstring process_name = m_umapPid2ProcessName[(DWORD)m_dwProcessId];
	switch (_original_opcode)
	{
	case EM_FileioEventOPC::FileioNameEvent:
	case EM_FileioEventOPC::FileioFileCreateEvent:
	case EM_FileioEventOPC::FileioCreateEvent:
		if (_detected_macro_file_record_map.find(_file_path) == _detected_macro_file_record_map.end())
		{
			if (isOfficeFile(_file_path) || isLoadByOffice(process_name))
			{
				_result = MacroDetector::GetInstance().DetectMacro(_file_path, _macro_contents);
				_detected_macro_file_record_map[_file_path] = _result;
			}
		}
		break;
	case EM_FileioEventOPC::FileIoWirte:
		if (_detected_macro_file_record_map.find(_file_path) != _detected_macro_file_record_map.end())
			_detected_macro_file_record_map.erase(_file_path);
		break;
	}

	return 0;
}

bool EventMacroResult::Output()
{
	if (_result != EM_MarcoDetectResult::isMalicious)	return false;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(m_eventIdentifier);
	if (ix != EventRecordManager::GetInstance().m_mapEventStrucp.end())
	{
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++)
		{
			if (ix->second[i].name == parameter_index_enum::MacroResult)
			{
				parameter_value.d = _result;
				m_vctParameterList.push_back(parameter_value);
			}
			else if (ix->second[i].name == parameter_index_enum::FileName)
			{
				parameter_value.s = _file_path;
				m_vctParameterList.push_back(parameter_value);
			}
			else if (ix->second[i].name == parameter_index_enum::MacroContent)
			{
				parameter_value.s = ToolFunctions::StringToWString(StringUtil::Join(_macro_contents, 0, "|"));
				m_vctParameterList.push_back(parameter_value);
			}
		}
	}
	return true;
}

EventRemovableDevice::EventRemovableDevice()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRemovableDevice);
}

EventRemovableDevice::~EventRemovableDevice()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRemovableDevice);
}

EventIpconfig::EventIpconfig()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventIpconfig);
}

EventIpconfig::~EventIpconfig()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventIpconfig);
}

EventHealthCheck::EventHealthCheck(const string& unique_id)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventHealthCheck);

	m_ulTimeStamp = 0;
	m_nProcessorId = 0;
	m_dwProcessId = 0;
	m_dwThreadId = 0;
	m_strCallstack = "";
	m_strEventName = "";

	m_eventIdentifier.event_name(m_strEventName);
	m_eventIdentifier.provider_id(ETWAddtionData);
	m_eventIdentifier.opcode(EM_AdditionDataEventOPC::HealthCheck);

	ParameterValue parameter_value;
	parameter_value.s = ToolFunctions::StringToWString(unique_id);
	m_vctParameterList.push_back(parameter_value);
}

EventHealthCheck::~EventHealthCheck()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventHealthCheck);
}

EventInitSignal::EventInitSignal()
{
	OBJECT_MEMORY_MONITOR_CTOR(EventHealthCheck);

	m_ulTimeStamp = 0;
	m_nProcessorId = 0;
	m_dwProcessId = 0;
	m_dwThreadId = 0;
	m_strCallstack = "";
	m_strEventName = "";

	m_eventIdentifier.event_name(m_strEventName);
	m_eventIdentifier.provider_id(ETWAddtionData);
	m_eventIdentifier.opcode(EM_AdditionDataEventOPC::InitSignal);

	uint_64 run_time = GetTickCount();
	time_t now_time;
	time(&now_time);
	int_32 device_boot_time = (int_32)(now_time - (run_time / 1000));

	ParameterValue parameter_value;
	parameter_value.d = device_boot_time;
	m_vctParameterList.push_back(parameter_value);
}

EventInitSignal::~EventInitSignal()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventHealthCheck);
}

EventAutorunInfo::EventAutorunInfo(const String& file_path)
{
	OBJECT_MEMORY_MONITOR_DTOR(EventAutorunInfo);

	m_ulTimeStamp = 0;
	m_nProcessorId = 0;
	m_dwProcessId = 0;
	m_dwThreadId = 0;
	m_strCallstack = "";
	m_strEventName = "";

	m_eventIdentifier.event_name(m_strEventName);
	m_eventIdentifier.provider_id(ETWAddtionData);
	m_eventIdentifier.opcode(EM_AdditionDataEventOPC::AutorunInfo);

	ParameterValue parameter_value;
	parameter_value.s = ToolFunctions::StringToWString(file_path);
	m_vctParameterList.push_back(parameter_value);
}

EventAutorunInfo::~EventAutorunInfo()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventAutorunInfo);
}

EventRansomCheck::EventRansomCheck()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRansomCheck);
}

EventRansomCheck::~EventRansomCheck()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRansomCheck);
}

EventRansomTerminate::EventRansomTerminate()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRansomTerminate);
}

EventRansomTerminate::~EventRansomTerminate()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRansomTerminate);
}

EventPowershellCheck::EventPowershellCheck()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventPowershellCheck);
}

EventPowershellCheck::~EventPowershellCheck()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventPowershellCheck);
}

EventZoneIdentifier::EventZoneIdentifier() {
    OBJECT_MEMORY_MONITOR_DTOR(EventZoneIdentifier);
}

EventZoneIdentifier::~EventZoneIdentifier() {
    OBJECT_MEMORY_MONITOR_DTOR(EventZoneIdentifier);
}

EventDriverLoaded::EventDriverLoaded() {
    OBJECT_MEMORY_MONITOR_DTOR(EventDriverLoaded);
}

EventDriverLoaded::~EventDriverLoaded() {
    OBJECT_MEMORY_MONITOR_DTOR(EventDriverLoaded);
}

EventProcessAccess::EventProcessAccess() {
    OBJECT_MEMORY_MONITOR_DTOR(EventProcessAccess);
}

EventProcessAccess::~EventProcessAccess() {
    OBJECT_MEMORY_MONITOR_DTOR(EventProcessAccess);
}

EventHashInfo::EventHashInfo() {
    OBJECT_MEMORY_MONITOR_DTOR(EventHashInfo);
}

EventHashInfo::~EventHashInfo() {
    OBJECT_MEMORY_MONITOR_DTOR(EventHashInfo);
}