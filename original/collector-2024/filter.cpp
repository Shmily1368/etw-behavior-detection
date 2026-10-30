#include "stdafx.h"
#include "filter.h"
#include <algorithm>
#include <fstream>
#include <sstream>
#include <io.h>

#include "event_record_manager.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "setting.h"
#include "thread_task_manager.h"
#include <windows.h>
#include <winternl.h>
#include <Shlwapi.h>
#include "RansomCheck.h"

std::set<std::wstring> Filter::m_setUselessAPIList;
std::unordered_set<uint_64> Filter::m_usetEventProcessWhiteList;
//not used
//std::set<EventIdentifier> Filter::event_output_white_list;
std::unordered_set<DWORD> Filter::m_usetPidBlackList;
std::unordered_set<DWORD> Filter::m_usetPidWhiteList;
std::unordered_set<std::string> Filter::m_usetApiNameWhiteList;
// registry
std::unordered_set<std::wstring> Filter::m_usetRegistryNameWhiteList;
std::set<DWORD> Filter::m_setRegistryPidWhiteList;
//not used
//std::set<DWORD> Filter::registry_pid_black_list;
// add by zxw on 20200811
std::unordered_map<DWORD, std::unordered_set<DWORD>> Filter::m_umapParent2ChildPid;
std::unordered_map<DWORD, std::unordered_set<DWORD>> Filter::m_umapPid2Tid;
std::unordered_set<DWORD> Filter::m_usetTidPrunerBlackList;
std::unordered_set<DWORD> Filter::m_usetPidPrunerBlackList;
std::unordered_set<DWORD> Filter::m_usetPidPrunerWhiteList;
std::unordered_map<DWORD, std::wstring> Filter::m_umapPid2FullPath;

std::set<int> Filter::m_setSystemcallAddressList;
//not used
//std::set<std::string> Filter::systemcall_name_list;
std::set<std::string> Filter::m_setSignatureSystemcallNameList;
std::set<EventIdentifier> Filter::m_setEventIdList;
std::set<EventIdentifier> Filter::m_setSignatureEventList;
std::string Filter::m_strSignatureFilePath = "C:\\Users\\research\\Desktop\\multify\\Reconstruction_Collector\\12.22_back";

// add by zxw on 20191119 添加ransom目录白名单、检测进程黑名单
std::set<std::wstring> Filter::m_setRansomDirWhiteList;
std::set<String> Filter::m_setRansomSuffixWhiteList;						// 添加ransom后缀白名单	
std::set<DWORD> Filter::m_setRansomPidBlackList;
//std::unordered_map<DWORD, DWORD> Filter::processid_parentid_map;		// 父子进程map表
std::set<SCertificateResult> Filter::m_setCertificateWhiteList;	// 添加企业证书白名单	

// add by zxw on 20191122 添加explorer pid特殊处理
DWORD Filter::m_dwExplorerPid;

void Filter::InsetUselessAPIList(std::wstring temp) 
{ 
	m_setUselessAPIList.insert(temp); 
}

bool Filter::QueryUselessAPIList(std::wstring temp) 
{ 
	return m_setUselessAPIList.count(temp); 
}

void Filter::Init()
{
	insert_process_id_black_list(-1);
	insert_process_id_black_list(GetCurrentProcessId());

	DEFINE_DLL_FUNCTION(NtQueryInformationProcess, LONG(WINAPI*)(HANDLE, UINT, PVOID, ULONG, PULONG), "ntdll.dll");
	if (NtQueryInformationProcess)
	{
		HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, GetCurrentProcessId());
		if (h_process)
		{
			PROCESS_BASIC_INFORMATION pbi;
			NTSTATUS ret = NtQueryInformationProcess(h_process, SystemBasicInformation, (PVOID)&pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
			if (NT_SUCCESS(ret))
			{
				WriteLog4cPlus(WARN_LEVEL, L"Init process_id = %d", (ULONG_PTR)pbi.Reserved3);
				//insert_process_id_black_list((ULONG_PTR)pbi.Reserved3);
                // collector start by client scheduler
                m_dwPrivilegePid = (ULONG_PTR)pbi.Reserved3;
			}

			CloseHandle(h_process);
		}
	}

	//just consume event in white list
	insert_event_process_white_list(ETWStackWalk, 32);

	for (auto iter : EventRecordManager::GetInstance().m_mapEventStrucp)
	{
		const EventIdentifier& event_identifier = iter.first;
		if (event_identifier.provider_id() == ETWPerfInfo &&
			InitCollector::GetCollector()->GetDetectorMode() == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK)
		{
			continue;
		}

		insert_event_process_white_list(event_identifier.provider_id(), event_identifier.opcode());
	}

#if defined(USE_LOCAL_TRUST_LIST)

	std::fstream super_white_list_file("super_white_list.ini", ios::in);
	String read_str;
	while (getline(super_white_list_file, read_str))
	{
		m_usetSuperWhiteListConfig.insert(StringUtil::ToLowerCase(read_str));
		WriteLog4cPlusA(INFO_LEVEL, "Filter::Init: add super white list config, name = %s", read_str.c_str());
	}

    STRING_VECTOR suffix_white_list;
    suffix_white_list.push_back("txt");
    suffix_white_list.push_back("doc");
    suffix_white_list.push_back("docx");
    suffix_white_list.push_back("ppt");
    suffix_white_list.push_back("pptx");
    suffix_white_list.push_back("xls");
    suffix_white_list.push_back("xlsx");
    suffix_white_list.push_back("wps");
    suffix_white_list.push_back("pdf");
    suffix_white_list.push_back("zip");
    suffix_white_list.push_back("md");
    suffix_white_list.push_back("ini");
    suffix_white_list.push_back("exe");
    AddRansomSuffixWhiteList(suffix_white_list, 0);
    WriteLog4cPlus(INFO_LEVEL, L"AddRansomSuffixWhiteList size = %d", suffix_white_list.size());

#endif

	m_emCurrentGear = (CollectorGear)Setting::GetInstance().collector_init_gear();
    // add by zxw on 20191216
    UpdateRansomDetector();
	// add by zxw on 20191120
	AddRansomWhiteDir();
	AddRansomRegistryWhiteList();
    // add by zxw on 20200724
    char cur_dir[MAX_PATH] = { 0 };
    GetCurrentDirectoryA(MAX_PATH, cur_dir);
    m_strAutorunsc64Path = cur_dir + std::string("\\") + AUTORUNSC64_PROCESS;
    m_strAutorunsc64Path.erase(0, 2);  // erase drive
    WriteLog4cPlusA(INFO_LEVEL, "Filter::Init _autorunsc64_path %s", m_strAutorunsc64Path.c_str());
}

void Filter::LogCacheSize() 
{
    if (Setting::GetInstance().enable_pruner_output())  
    {
        WriteLog4cPlus(DEBUG_LEVEL, L"Filter::tid_pruner_black_list: %d", m_usetTidPrunerBlackList.size());
        WriteLog4cPlus(DEBUG_LEVEL, L"Filter::pid_pruner_black_list: %d", m_usetPidPrunerBlackList.size());
        WriteLog4cPlus(DEBUG_LEVEL, L"Filter::pid_pruner_white_list: %d", m_usetPidPrunerWhiteList.size());

        WriteLog4cPlus(DEBUG_LEVEL, L"Filter::parentid2childid_map_: %d", m_umapParent2ChildPid.size());
        WriteLog4cPlus(DEBUG_LEVEL, L"Filter::pid2tid_map_: %d", m_umapPid2Tid.size());
    }
}

bool Filter::FilterBeforeRecInstance(uint_32 provider_id, int_32 opcode, DWORD process_id)
{
	uint_64 nProvider_id = (uint_64)provider_id * 100 + opcode;
	auto iter = m_usetEventProcessWhiteList.find(nProvider_id);
	if (iter == m_usetEventProcessWhiteList.end())
		return false;
    // add by zxw on 20200509
    if (provider_id != ETWProcess)
    {
        if (IsSuperWhiteListProcess(process_id))	
			return false;
    }	
	if (_FilterByGear(process_id, provider_id))	
		return false;

	// Filter Win10 special event;
	switch (provider_id)
	{
	case ETWFileIo:
		if (opcode == EM_FileioEventOPC::FileIoRenamePath)	return false;
        // add by zxw 20191213 filter FileIoCleanup & FileioDirEnumerationEvent if not ransom
        if (!Setting::GetInstance().enable_ransom_detector())
        {
            if (opcode == EM_FileioEventOPC::FileIoCleanup || opcode == EM_FileioEventOPC::FileioDirEnumerationEvent)
            {
                return false;
            }
        }
        //
		break;

	case ETWProcess:
		if (opcode == EM_ProcessEventOPC::ProcessDCEnd)	return false;
		break;
    case ETWRegistry:
        if (opcode == EM_RegistryEventOPC::RegistryQuery || 
            opcode == EM_RegistryEventOPC::RegistrySetInformation||
            opcode == EM_RegistryEventOPC::RegistryQueryValue)
        {
            // add by zxw on 20200519
            if (!Setting::GetInstance().enable_debug_output() && !Setting::GetInstance().enable_ransom_detector())
                return false;
        }
        if (process_id == m_dwExplorerPid || process_id == 4)
        {          
            return false;
        }
        break;
    // add by zxw on 20200811 if enable_pruner_output= true prun all TcpIpRecvIPV4
    case ETWTcpIp:
        if (Setting::GetInstance().enable_pruner_output() && opcode == EM_TcpIpEventOPC::TcpIpRecvIPV4)	return false;
        break;
        
	default:
		break;
	}

	return true;
}

bool Filter::FilterAfterRecInstance(EventRecord* rec)
{
    // add by zxw on 20200509
    auto provider_id = rec->get_event_identifier_().provider_id();
    if (provider_id != ETWProcess)
    {
        if (IsSuperWhiteListProcess(rec->get_process_id_()))	
			return false;
        // add by zxw on 20200820
        if (Setting::GetInstance().enable_pruner_output() && provider_id != ETWStackWalk) {
            if (m_usetPidPrunerWhiteList.find(rec->get_process_id_()) != m_usetPidPrunerWhiteList.end()) {
                if (m_usetTidPrunerBlackList.find(rec->get_thread_id_()) == m_usetTidPrunerBlackList.end())
                    return false;
            }
        }
    }

	if (!FilterRegRecInstance(rec)) return false;

	if (_FilterByGear(rec->get_process_id_(), provider_id))	return false;

	return true;
}

bool Filter::FilterRegRecInstance(EventRecord* rec)
{
	if (Setting::GetInstance().enable_ransom_detector())
	{
		if (rec->get_event_identifier_().provider_id() == ETWRegistry)
		{
			auto pid = rec->get_process_id_();
			if (Filter::query_registry_pid_white_list(pid)) return false;
		}
	}
	return true;
}

std::wstring Utf8ToWideChar(
	_In_ CONST std::string& strSrc
)
{
	std::wstring wstrRet = L"";

	int nLengthB = 0;
	PWCHAR pwchBuffer = NULL;


	do
	{
		if (strSrc.empty())
		{
			break;
		}

		nLengthB = MultiByteToWideChar(CP_UTF8, 0, strSrc.c_str(), (int)strSrc.length(), NULL, 0);
		if (0 == nLengthB)
		{
			break;
		}

		nLengthB += 1;

		pwchBuffer = (PWCHAR)calloc(1, nLengthB * sizeof(WCHAR));
		if (NULL == pwchBuffer)
		{
			break;
		}

		nLengthB = MultiByteToWideChar(CP_UTF8, 0, strSrc.c_str(), (int)strSrc.length(), pwchBuffer, nLengthB);
		if (0 == nLengthB)
		{
			break;
		}

		wstrRet = pwchBuffer;
	} while (FALSE);

	if (NULL != pwchBuffer)
	{
		free(pwchBuffer);
		pwchBuffer = NULL;
	}

	return wstrRet;
}

bool
Filter::IsWhite(
	_In_ CONST std::wstring& wstrPath
)
{
	bool bRet = FALSE;

	do
	{
		
		if (NULL != PathMatchSpec(wstrPath.c_str(), L"*\\System32\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\Windows\\*")
#if 0
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\Program Files (x86)\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\ProgramData\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\Users\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\SysWOW64\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\Program Files\\*")
			|| NULL != PathMatchSpec(wstrPath.c_str(), L"*\\Windows\\*")
#endif
			)
		{
			bRet = TRUE;
			break;
		}
	} while (FALSE);

	return bRet;
}

bool Filter::IsSuperWhiteListProcess(DWORD pid)
{
	if (pid == ULONG_MAX)
	{
		return false;
	}
    // add by zxw on 20200724
    if (m_dwAutorunsc64Pid != 0 && pid == m_dwAutorunsc64Pid)
    {
        return true;
    }
    
	while (m_queueSuperWhiteListConfigRemoveBuffer.size_approx() > 0)
	{
		String file_name;
		if (m_queueSuperWhiteListConfigRemoveBuffer.try_dequeue(file_name))
		{
			m_lockProcessFilterData.ReadLock();
			_OnRemoveSuperWhiteList(file_name);
			m_lockProcessFilterData.ReadUnlock();
		}
	}

	while (m_queueSuperWhiteListConfigAddBuffer.size_approx() > 0)
	{
		String file_name;
		if (m_queueSuperWhiteListConfigAddBuffer.try_dequeue(file_name))
		{
			m_lockProcessFilterData.ReadLock();
			_OnAddSuperWhiteList(file_name);
			m_lockProcessFilterData.ReadUnlock();
		}
	}
	
	while (m_queueSuperWhiteListWaitBuffer.size_approx() > 0)
	{
		ProcessFilterData data;
		if (m_queueSuperWhiteListWaitBuffer.try_dequeue(data))
		{
			BOOL bAddWhiteList = FALSE;
			if (data.file_name != EMPTY_STRING)
			{
// #ifdef ETW_FILTER_TEST
// 				char szTemp[50] = { 0 };
// 				StringHelp::StringFormatA(szTemp, 50, "%d,%d,%d,%d,%d,"
// 					, 1
// 					, 1
// 					, data.process_id
// 					, 1
// 					, 1);
// 				std::string strT = szTemp;
// 				strT += "AddWhiteList:  ";
// 				strT += data.file_path;
// 				g_thCRC.AddLine("add", strT.c_str());
// #endif // ETW_FILTER_TEST


				if (Setting::GetInstance().enable_process_whitelist())
				{
					std::wstring wstrPath = CPykMgrTemplate<CP_ACP>(data.file_path.c_str());
					if (m_usetSuperWhiteListConfig.find(StringUtil::ToLowerCase(data.file_name)) != m_usetSuperWhiteListConfig.end()
						//|| IsWhite(wstrPath)
						)
					{
						bAddWhiteList = TRUE;
					}
				}
				else
				{
					if (m_usetSuperWhiteListConfig.find(StringUtil::ToLowerCase(data.file_name)) != m_usetSuperWhiteListConfig.end())
					{
						bAddWhiteList = TRUE;
					}
				}

				if (RansomCheck::getDetectFlag())
				{
					RansomCheck::addRansomWhiteList(data.process_id);
				}
			}	
			if(bAddWhiteList)
			{
				m_usetSuperWhiteList.insert(data.process_id);				
				WriteLog4cPlusA(WARN_LEVEL, "IsSuperWhiteListProcess: process_id = %d,%s,%s", data.process_id, data.file_name.c_str(), data.file_path.c_str());
			}
		}
	}

	if (RansomCheck::getDetectFlag() && RansomCheck::checkRansomPid(pid)) return false;
	// add by zxw on 20210511
    if (IsCertificateWhiteListProcess(pid))
    {
        return true;
    }
    
	return m_usetSuperWhiteList.find(pid) != m_usetSuperWhiteList.end();
}

bool Filter::IsSuperWhiteListProcessEx(DWORD pid) {
    if (pid == ULONG_MAX) {
        return false;
    }
    // add by zxw on 20200724
	if (m_dwAutorunsc64Pid != 0 && pid == m_dwAutorunsc64Pid)
		return true;

	bool bResult = false;
	do
	{
		if (RansomCheck::getDetectFlag())
		{
			bResult = (!RansomCheck::checkRansomPid(pid)
				&& m_usetSuperWhiteList.find(pid) != m_usetSuperWhiteList.end());
			break;
		}
		bResult = m_usetSuperWhiteList.find(pid) != m_usetSuperWhiteList.end();
	} while (false);
	if (bResult)
	{
		WriteLog4cPlusA(INFO_LEVEL, "checkRansomPid %d,%d,%d", pid, bResult, m_usetSuperWhiteList.count(pid));
	}
	return bResult;
}

bool Filter::IsPrivilegeProcess(DWORD pid)
{
	if (pid != 0 && m_dwPrivilegePid == pid)
	{
		return true;
	}
	return false;	
}

bool Filter::SetLoclaIPbyEventRecord(EventRecordTcpip* rec)
{
	if (rec != nullptr)
	{
		auto event_identifier = rec->get_event_identifier_();
		if ((rec->get_process_id_() == m_dwPrivilegePid) && (event_identifier.provider_id() == ETWTcpIp))
		{
			EM_TcpIpEventOPC opcode = (EM_TcpIpEventOPC)event_identifier.opcode();
			if (opcode == EM_TcpIpEventOPC::TcpIpSendIPV4)
			{
				uint_64 s_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::saddr);
				uint_16 s_port = (uint_16)rec->GetDataParameter(parameter_index_enum::sport);
				uint_64 d_ip = (uint_64)rec->GetDataParameter(parameter_index_enum::daddr);
				uint_16 d_port = (uint_16)rec->GetDataParameter(parameter_index_enum::dport);
				auto ip_port = ToolFunctions::Net2Str(d_ip) + ":" + to_string(ntohs(d_port));
				if (Setting::GetInstance().kafka_address() == ip_port)
				{
					auto sip = ToolFunctions::Net2Str(s_ip);
					if (m_strLocalIp != sip)
					{
						WriteLog4cPlusA(INFO_LEVEL, "Update localIP old IP= %s new IP = %s",m_strLocalIp.c_str(), sip.c_str());

						m_strLocalIp = sip;
						return true;
					}							
				}				
			}
		}
	}
	return false;
}

std::string Filter::GetLocalIP()
{
	return m_strLocalIp;
}

EventRecord* Filter::APIFilter(EventRecord* record) 
{
	if (record->get_event_identifier_().provider_id() == ETWStackWalk
		&& !m_usetApiNameWhiteList.count(record->get_callstack_())) {
		delete record;
		return NULL;
	}
	return record;
}

bool Filter::FilterAfterParseRecord(EventRecord* record) 
{
    // add by zxw on 20200511
    auto provider_id = record->get_event_identifier_().provider_id();
	auto pid = record->get_process_id_();
    if (provider_id != ETWProcess)
    {
        auto tid = record->get_thread_id_();
        if (m_usetPidWhiteList.size() != 0 && m_usetPidWhiteList.find(pid) == m_usetPidWhiteList.end())
        {
            return false;
        }

        if (m_usetPidBlackList.count(pid))
        {
            return false;
        }

        // add by zxw on 20200811
        if (Setting::GetInstance().enable_pruner_output() && provider_id != ETWStackWalk) {
            if (m_usetPidPrunerWhiteList.find(pid) != m_usetPidPrunerWhiteList.end())
            {
                if (m_usetTidPrunerBlackList.find(tid) == m_usetTidPrunerBlackList.end())
                    return false;
            }
        }
    }
	
	// mod by zxw on 20191128 ransom模块需要先不处理，output模块再裁剪
    if (!RansomCheck::getDetectFlag())
	{
        if (record->isUseless())
        {
            return false;
        }
    }
    else
    {
        // 非FileIo事件过滤
        if (provider_id != ETWFileIo)
        {
            if (record->isUseless())
            {
                return false;
            }
        }
    }

	if (!Filter::GetInstance().FilterRegRecInstance(record)) return false;
	
	return true;
}

void Wchar_tToString(std::string& szDst, wchar_t *wchar)
{
	wchar_t * wText = wchar;
	char* psText;
	DWORD dwNum = WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, NULL, 0, NULL, FALSE);
	psText = new char[dwNum];
	WideCharToMultiByte(CP_OEMCP, NULL, wText, -1, psText, dwNum, NULL, FALSE);
	szDst = psText;
	delete[]psText;
}

void Filter::set_signature_file_path(std::string path)
{
	m_strSignatureFilePath = path;
}

void Filter::OnExeImageLoad(DWORD pid, const String& file_path)
{

// #ifdef ETW_FILTER_TEST
// 	char szTemp[50] = { 0 };
// 	StringHelp::StringFormatA(szTemp, 50, "%d,%d,%d,%d,%d,"
// 		, 1
// 		, 1
// 		, 1
// 		, 1
// 		, 1);
// 	std::string strT = szTemp;
// 	strT += "OnExeImageLoad:  ";
// 	strT += file_path;
// 	g_thCRC.AddLine("add", strT.c_str());
// #endif // ETW_FILTER_TEST


	ProcessFilterData* data = new ProcessFilterData();
	data->process_id = pid;
	data->file_path = file_path;
	STRING_VECTOR file_path_parts;
	StringUtil::split(file_path, '\\', file_path_parts);
	data->file_name = file_path_parts.empty() ? EMPTY_STRING : file_path_parts.back();
	data->certificate_result = EM_CertificateResult::CERTIFICATE_RESULT__UNDETERMINED;
	m_lockProcessFilterData.WriteLock();
	m_umapProcessFilterData.insert(std::make_pair(pid, data));
	m_lockProcessFilterData.WriteUnlock();
	// ADD BY ZXW 20191029 检测特权进程
	if (m_dwPrivilegePid == 0 && StringUtil::ToLowerCase(data->file_name) == PRIVILEGE_PROCESS)
	{
		m_dwPrivilegePid = pid;
		WriteLog4cPlus(INFO_LEVEL, L"update _privilege_pid %d", m_dwPrivilegePid);
	}
	// ADD BY ZXW ON 20191122 EXPLORER_PROCESS
	if (StringUtil::ToLowerCase(data->file_name) == EXPLORER_PROCESS)
	{
		m_dwExplorerPid = pid;
		WriteLog4cPlus(INFO_LEVEL, L"update _explorer_pid %d", m_dwExplorerPid);
	}
    // ADD BY ZXW 20200724 检测特权进程
    if (file_path == m_strAutorunsc64Path) {
        m_dwAutorunsc64Pid = pid;
        WriteLog4cPlus(INFO_LEVEL, L"update _autorunsc64_pid %d", m_dwAutorunsc64Pid);
    }
    
	//
}

void Filter::OnExeCertificateResult(DWORD pid, EM_CertificateResult result)
{
	m_lockProcessFilterData.WriteLock();

	auto iter_f = m_umapProcessFilterData.find(pid);
	if (iter_f != m_umapProcessFilterData.end())
	{
		ProcessFilterData* data = iter_f->second;
		std::wstring wstrPath = CPykMgrTemplate<CP_ACP>(data->file_path.c_str());
		if (data->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__UNDETERMINED)
		{
			data->certificate_result = result;

			if (result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL && data != nullptr)
			{
				m_queueSuperWhiteListWaitBuffer.enqueue(*data);
			}
			else
				if (Setting::GetInstance().enable_process_whitelist())
				{
					if (IsWhite(wstrPath))
					{
						m_queueSuperWhiteListWaitBuffer.enqueue(*data);
					}
				}
		}
		else
			if (Setting::GetInstance().enable_process_whitelist())
			{
				if (IsWhite(wstrPath))
				{
					m_queueSuperWhiteListWaitBuffer.enqueue(*data);
				}
			}
	}
    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output())
    {
        if (result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL)             
        {
            // if pid is not exit and pid is not in blacklist add white list
            if (EventRecord::query_process_id2process_name_map_(pid) && m_usetPidPrunerBlackList.find(pid) == m_usetPidPrunerBlackList.end())
                insert_pid_pruner_white_list(pid);            
        }            
        else {
            if (EventRecord::query_process_id2process_name_map_(pid))
            {
                // 移除白名单
                erase_pid_pruner_white_list(pid);
                // 添加黑名单
                insert_pid_pruner_black_list(pid);
                // add child pid in black list
                auto iter = m_umapParent2ChildPid.find(pid);
                if (iter != m_umapParent2ChildPid.end()) {
                    for each (auto var in iter->second) {
                        if (EventRecord::query_process_id2process_name_map_(var))   
                        {
                            // 移除白名单
                            erase_pid_pruner_white_list(var);
                            // 添加黑名单
                            insert_pid_pruner_black_list(var);
                        }
                      
                    }
                }
                // add tid in black list
                auto iter1 = m_umapPid2Tid.find(pid);
                if (iter1 != m_umapPid2Tid.end()) {
                    for each (auto var in iter1->second) {
                        insert_tid_pruner_black_list(var);
                    }
                }
            }
               
        }
        m_umapPid2Tid.erase(pid);
        m_umapParent2ChildPid.erase(pid);
    }
    //
	m_lockProcessFilterData.WriteUnlock();
}

void Filter::OnProcessEnd(DWORD pid)
{
	m_usetSuperWhiteList.erase(pid);
	if (RansomCheck::getDetectFlag())
	{
		RansomCheck::removeRansomWhiteList(pid);
	}
	DelFullPath(pid);
	m_lockProcessFilterData.WriteLock();
	auto iter_f = m_umapProcessFilterData.find(pid);
	if (iter_f != m_umapProcessFilterData.end())
	{
		SAFE_DELETE(iter_f->second);
		m_umapProcessFilterData.erase(iter_f);
	}

    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output()) {
        erase_pid_pruner_white_list(pid);
        erase_pid_pruner_black_list(pid);
        m_umapPid2Tid.erase(pid);
        m_umapParent2ChildPid.erase(pid);
        for (auto iter = m_umapParent2ChildPid.begin(); iter != m_umapParent2ChildPid.end(); iter++)
        {          
            auto pidset = iter->second;
            if (pidset.find(pid) != pidset.end())
            {
                pidset.erase(pid);
            }            
        }
    }    

	m_lockProcessFilterData.WriteUnlock();
}

void Filter::OnProcessStart(EventRecordProcess * rec) 
{
    if (Setting::GetInstance().enable_pruner_output()) {
        m_lockProcessFilterData.WriteLock();

        auto  pid = rec->GetDataParameter(parameter_index_enum::ProcessId);
        auto parentid = rec->GetDataParameter(parameter_index_enum::ParentId);
        if (m_usetPidPrunerBlackList.find(parentid) == m_usetPidPrunerBlackList.end())   
        {
            if (m_usetPidPrunerWhiteList.find(parentid) == m_usetPidPrunerWhiteList.end())
                m_umapParent2ChildPid[parentid].insert(pid);
        }            
        else 
        {
            // 移除白名单
            erase_pid_pruner_white_list(pid);
            // 添加黑名单
            insert_pid_pruner_black_list(pid);
        }

        m_lockProcessFilterData.WriteUnlock();
    }
}

void Filter::OnThreadEnd(DWORD tid, DWORD pid)
{
    // add by zxw on 20200811
    if (Setting::GetInstance().enable_pruner_output()) 
    {
        m_lockProcessFilterData.WriteLock();

        erase_tid_pruner_black_list(tid);

        auto iter = m_umapPid2Tid.find(pid);
        if (iter != m_umapPid2Tid.end())
            iter->second.erase(tid);

        m_lockProcessFilterData.WriteUnlock();
    }
}

void Filter::OnThreadStart(EventRecordThread * rec) 
{
    auto ppid = rec->get_process_id_();
    auto ptid = rec->get_thread_id_();
    auto tid = rec->GetDataParameter(parameter_index_enum::TThreadId);
    auto pid = rec->GetDataParameter(parameter_index_enum::ProcessId);
    if (Setting::GetInstance().enable_pruner_output()) 
    {      
        m_lockProcessFilterData.WriteLock(); 

        if (m_usetTidPrunerBlackList.size() > 0 && m_usetTidPrunerBlackList.find(ptid) != m_usetTidPrunerBlackList.end())       
        {
            insert_tid_pruner_black_list(tid);
            m_lockProcessFilterData.WriteUnlock();
            return;
        }

        if (m_usetPidPrunerBlackList.find(ppid) != m_usetPidPrunerBlackList.end())
        {

            insert_tid_pruner_black_list(tid);
            m_lockProcessFilterData.WriteUnlock();
            return;
        }
        
        if (m_usetPidPrunerWhiteList.find(ppid) == m_usetPidPrunerWhiteList.end())
        {
            m_umapPid2Tid[ppid].insert(tid);
        }        

        m_lockProcessFilterData.WriteUnlock();

    }
}

void Filter::OnPhfDetectorResult(DWORD pid)
{
    m_lockProcessFilterData.WriteLock();

    if (Setting::GetInstance().enable_pruner_output() && EventRecord::query_process_id2process_name_map_(pid))
    {       
        // 移除白名单
        erase_pid_pruner_white_list(pid);
        // 添加黑名单
        insert_pid_pruner_black_list(pid);
    }

    m_lockProcessFilterData.WriteUnlock();
}

bool Filter::IsProcessCertificate(DWORD pid) const
{
	m_lockProcessFilterData.ReadLock();

	auto iter_f = m_umapProcessFilterData.find(pid);
	bool result = iter_f != m_umapProcessFilterData.end() && iter_f->second->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL;

	m_lockProcessFilterData.ReadUnlock();

	return result;
}

void Filter::InitSuperWhiteList(const STRING_VECTOR& list_init)
{
	for (const String& file_name : list_init)
	{
		m_queueSuperWhiteListConfigAddBuffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::AddSuperWhiteList(const STRING_VECTOR& list_add)
{
	for (const String& file_name : list_add)
	{
		m_queueSuperWhiteListConfigAddBuffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::RemoveSuperWhiteList(const STRING_VECTOR& list_remove)
{
	for (const String& file_name : list_remove)
	{
		m_queueSuperWhiteListConfigRemoveBuffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
}

void Filter::ChangeSuperWhiteList(const String& file_name_s, const String& file_name_d)
{
	m_queueSuperWhiteListConfigAddBuffer.enqueue(StringUtil::ToLowerCase(file_name_d));
	m_queueSuperWhiteListConfigRemoveBuffer.enqueue(StringUtil::ToLowerCase(file_name_s));
}

void Filter::AddRansomSuffixWhiteList(const STRING_VECTOR & list_add, int is_terminate)
{
	moodycamel::ConcurrentQueue<String>().swap(m_queueRansomSuffixWhiteListAddBuffer);
	for (const String& file_name : list_add)
	{
		m_queueRansomSuffixWhiteListAddBuffer.enqueue(StringUtil::ToLowerCase(file_name));
	}
    // add by zxw on 20210513
    m_bRanssomIsTerminate = is_terminate;
}

void Filter::UpdateRansomDetector()
{
    // add on 20191216 m_collector_init_gear > CollectorGear::COLLECTOR_GEAR__2 or m_local_detector_mode != "callstack" close m_enable_ransom_detector
    if (Setting::GetInstance().local_detector_mode() != "callstack")
    {
        m_bCurrentRansomDetector = false;
        return;
    }
    /*
    // add on 20200102 if not safe mode close ransom
    if (Setting::GetInstance().enable_gear_adjustment() || Setting::GetInstance().enable_hardware_adjustment())
    {
        _current_ransom_detector = false;
        return;
    }
    //
    */
    if (m_emCurrentGear > CollectorGear::COLLECTOR_GEAR__2)
    {
        m_bCurrentRansomDetector = false;
    }
    else
    {
        m_bCurrentRansomDetector = Setting::GetInstance().enable_ransom_detector();
    }       
}

void Filter::RuleMatchSwitch(std::string rule_match) 
{
    if (rule_match == "0") {
        ThreadTaskManager::GetInstance().StopTask(EM_ThreadTaskMode::RULE_MATCHER_TASK_MODE);
    }
    else {
        ThreadTaskManager::GetInstance().AddTask(EM_ThreadTaskMode::RULE_MATCHER_TASK_MODE);
    }
}

void Filter::AddCertificateWhiteListBuffer(const std::vector<SCertificateResult>& list_add)
{
    moodycamel::ConcurrentQueue<SCertificateResult>().swap(m_queueCertificateWhiteListAddBuffer);
    for (auto certificate_data : list_add) {
        m_queueCertificateWhiteListAddBuffer.enqueue(certificate_data);
    }
}

bool Filter::IsInCertificateWhiteList(std::string thumbPrint, std::string subjectname)
{
    // 添加
    if (m_queueCertificateWhiteListAddBuffer.size_approx() > 0) {
        std::set<SCertificateResult>().swap(m_setCertificateWhiteList);
        while (m_queueCertificateWhiteListAddBuffer.size_approx() > 0) {
            SCertificateResult scert;
            if (m_queueCertificateWhiteListAddBuffer.try_dequeue(scert)) {
                m_setCertificateWhiteList.insert(scert);
            }
        }
    }
    // 查询
    auto it = m_setCertificateWhiteList.begin();
    while (it != m_setCertificateWhiteList.end())
    {
        if (it->thumbPrint.size() > 0)
        {
            if (it->thumbPrint == thumbPrint && it->subjectname == subjectname) 
            {
                return true;
            }
        }
        else {
            if (it->subjectname == subjectname) 
            {
                return true;
            }
        } 

        it++;
    }
    return false;
}

void Filter::AddSurpCertificateWhiteListBuffer(DWORD pid) 
{
    if (pid > 0 && pid != ULONG_MAX)
        m_queueSuperCertificateWhiteListAddBuffer.enqueue(pid);
}

bool Filter::IsCertificateWhiteListProcess(DWORD pid) 
{
    if (pid == ULONG_MAX) {
        return false;
    }
   
    if (m_dwAutorunsc64Pid != 0 && pid == m_dwAutorunsc64Pid) {
        return true;
    }
    
    while (m_queueSuperCertificateWhiteListAddBuffer.size_approx() > 0) 
    {
        DWORD process_id;
        if (m_queueSuperCertificateWhiteListAddBuffer.try_dequeue(process_id)) {
            if (EventRecord::query_process_id2process_name_map_(process_id))
            {
                m_usetSuperCertificateWhiteList.insert(process_id);
                WriteLog4cPlus(DEBUG_LEVEL, L"Filter add certificate super white list process, pid = %d", process_id);
            }
        }
    }

    return m_usetSuperCertificateWhiteList.find(pid) != m_usetSuperCertificateWhiteList.end();
}

String Filter::GetProcessFileName(DWORD pid) const
{
	String file_name = EMPTY_STRING;
	
	m_lockProcessFilterData.ReadLock();
	auto iter = m_umapProcessFilterData.find(pid);
	if (iter != m_umapProcessFilterData.end())
	{
		file_name = iter->second->file_name;
	}
	m_lockProcessFilterData.ReadUnlock();

	return file_name;
}

void Filter::SetCollectorGear(CollectorGear gear)
{
	if (!Setting::GetInstance().enable_gear_adjustment())	return;
    // add by zxw on 20200409 honey pot close change gear
    if (Setting::GetInstance().enable_honey_pot())	return;

	m_emCurrentGear = gear;
	if (m_emCurrentGear >= CollectorGear::COLLECTOR_GEAR__3)
	{
		ThreadTaskManager::GetInstance().StopTask(EM_ThreadTaskMode::GET_VISIBLE_WINDOW_TASK_MODE);
	}
	else
	{
		ThreadTaskManager::GetInstance().AddTask(EM_ThreadTaskMode::GET_VISIBLE_WINDOW_TASK_MODE);
	}
    // add by zxw on 20191216
    UpdateRansomDetector();
}

CollectorGear Filter::GetCollectorGear()
{
	return m_emCurrentGear;
}

void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname)
{

	intptr_t   hFile = 0;
	struct _finddata_t fileinfo;
	std::string p;
	if ((hFile = _findfirst(p.assign(path).append("\\*").c_str(), &fileinfo)) != -1)
	{
		do
		{
			if ((fileinfo.attrib &  _A_SUBDIR))
			{
				if (strcmp(fileinfo.name, ".") != 0 && strcmp(fileinfo.name, "..") != 0)
					getFiles(p.assign(path).append("\\").append(fileinfo.name), files, ownname); 
			}
			else
			{
				files.push_back(p.assign(path).append("\\").append(fileinfo.name));
				ownname.push_back(fileinfo.name);
			}
		} while (_findnext(hFile, &fileinfo) == 0);
		_findclose(hFile);
	}
}

//Filter::Filter(){
//	provider_modulo_mapping_hash[0xcd] = 0;//ALPC
//	provider_modulo_mapping_hash[0xd1] = 1;//Thread
//	provider_modulo_mapping_hash[0x39] = 2;//FileIO
//	provider_modulo_mapping_hash[0xd4] = 3;//DiskIO
//	provider_modulo_mapping_hash[0xb4] = 4;//PerfInfo
//	provider_modulo_mapping_hash[0xd3] = 5;//PageFault
//	provider_modulo_mapping_hash[0xc0] = 6;//Tcp
//	provider_modulo_mapping_hash[0xc5] = 7;//Udp
//	provider_modulo_mapping_hash[0xd0] = 8;//Process
//	provider_modulo_mapping_hash[0x2e] = 9;//Registry
//	provider_modulo_mapping_hash[0x92] = 10;//Splitlo
//	for (int i = 0; i != KProviderSize; i++){
//		for (int j = 0; j != KOpcodeSize; j++){
//			event_filter_list[i][j] = 0;
//		}
//	}
//}

bool Filter::isSystemCallNeeded(int Address)
{
	if (m_setSystemcallAddressList.count(Address)) return true;
	return false;
}

bool Filter::isEventNeeded(EventIdentifier ID)
{
	if (m_setEventIdList.count(ID)) return true;
	return false;
}

bool Filter::AddSystemCall(int Address)
{
	m_setSystemcallAddressList.insert(Address);
	return 1;
}

bool Filter::AddEvent(EventIdentifier ID)
{
	m_setEventIdList.insert(ID);
	return 1;
}

bool Filter::DelSystemCall(int Address)
{
	std::set<int>::iterator ix = m_setSystemcallAddressList.find(Address);
	if (ix == m_setSystemcallAddressList.end()) return 0;
	m_setSystemcallAddressList.erase(ix);
	return 1;
}

bool Filter::DelEvent(EventIdentifier ID)
{
	std::set<EventIdentifier>::iterator ix = m_setEventIdList.find(ID);
	if (ix == m_setEventIdList.end()) return 0;
	m_setEventIdList.erase(ix);
	return 1;
}

String Filter::GetEventName(EventIdentifier ID) {
    std::set<EventIdentifier>::iterator ix = m_setEventIdList.find(ID);
    if (ix == m_setEventIdList.end()) return "";
    return ix->event_name();
}

size_t Filter::QuerySystemCallListSize()
{
	return m_setSystemcallAddressList.size();
}

size_t Filter::QueryEventListSize()
{
	return m_setEventIdList.size();
}

//void Filter::CreatEnableFlag()
//{
//
//}

//int Filter::get_enableflag()
//{
//	if (!enableflag) CreatEnableFlag();
//	return enableflag;
//}

void inline Filter::InsertEventIdentifier(EventIdentifier event_indentifier)
{
	//if event_identifier not in the set && in the format,insert it
	std::set<EventIdentifier>::iterator ix = m_setEventIdList.find(event_indentifier);
	if (ix!=m_setEventIdList.end()&&m_setSignatureEventList.find(event_indentifier) == m_setSignatureEventList.end()) m_setSignatureEventList.insert(*ix);
}

bool Filter::_FilterByGear(DWORD process_id, uint_32 provider_id) const
{
	if (m_emCurrentGear >= CollectorGear::COLLECTOR_GEAR__2)
	{
		if ((provider_id == ETWStackWalk || provider_id == ETWPerfInfo) && (m_emCurrentGear >= CollectorGear::COLLECTOR_GEAR__3 || Filter::GetInstance().IsProcessCertificate(process_id)))
		{
			return true;
		}

		if (m_emCurrentGear >= COLLECTOR_GEAR__4 && provider_id == ETWFileIo)
		{
			return true;
		}

		if (m_emCurrentGear == COLLECTOR_GEAR__5 && provider_id != ETWThread && provider_id != ETWProcess)
		{
			return true;
		}
	}

	return false;
}

void Filter::_OnAddSuperWhiteList(const String& file_name)
{
	m_usetSuperWhiteListConfig.insert(file_name);
	for (auto pair_t : m_umapProcessFilterData)
	{
		ProcessFilterData* data = pair_t.second;
		if (data->file_path.find(file_name) != String::npos &&
			data->certificate_result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL)
		{
			m_usetSuperWhiteList.insert(data->process_id);
			WriteLog4cPlus(WARN_LEVEL, L"Filter::_OnAddSuperWhiteList: process_id = %d", data->process_id);
		}
	}
}

void Filter::_OnRemoveSuperWhiteList(const String& file_name)
{
	m_usetSuperWhiteListConfig.erase(file_name);
	for (auto pair_t : m_umapProcessFilterData)
	{
		ProcessFilterData* data = pair_t.second;
		if (data->file_path.find(file_name) != String::npos)
		{
			m_usetSuperWhiteList.erase(data->process_id);
			WriteLog4cPlus(WARN_LEVEL, L"Filter::_OnRemoveSuperWhiteList: process_id = %d", data->process_id);
		}
	}
}

void Filter::AddRansomWhiteDir()
{
	TCHAR curdir[MAX_PATH]; 
	GetCurrentDirectory(MAX_PATH, curdir);
	// 添加当前目录作为白名单
	insert_ransom_dir_white_list(curdir);
	WriteLog4cPlus(INFO_LEVEL, L"Filter::AddRansomWhiteDir: %s", curdir);
	/*
	std::fstream fp;
	String read_str;
	fp.open("ransom_dir_white_list.ini", ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			insert_ransom_dir_white_list(ToolFunctions::StringToWString(read_str));
		}
		fp.close();
	}else
		;
	*/
}

void Filter::AddRansomRegistryWhiteList()
{
	if (Setting::GetInstance().enable_ransom_detector())
	{
		m_usetRegistryNameWhiteList.insert(L"MSTool.exe");
		m_usetRegistryNameWhiteList.insert(L"msvsmon.exe");
		m_usetRegistryNameWhiteList.insert(L"windbg.exe");
		m_usetRegistryNameWhiteList.insert(L"Microsoft Visual Studio");
		m_usetRegistryNameWhiteList.insert(L"VisualStudio");
		m_usetRegistryNameWhiteList.insert(L"\\Microsoft.NET\\");
		m_usetRegistryNameWhiteList.insert(L"AsiaInfo");
		m_usetRegistryNameWhiteList.insert(L"\\LVUAAgentInstBaseRoot\\");
		m_usetRegistryNameWhiteList.insert(L"\\Sangfor\\");
		m_usetRegistryNameWhiteList.insert(L"\\SkyGuard\\");
		m_usetRegistryNameWhiteList.insert(L"\\LANDesk\\");
		m_usetRegistryNameWhiteList.insert(L"\\virtio\\");
		m_usetRegistryNameWhiteList.insert(L"\\Huawei\\");
		m_usetRegistryNameWhiteList.insert(L"\\Xen PV Drivers\\");
		m_usetRegistryNameWhiteList.insert(L"\\360safe\\");
		m_usetRegistryNameWhiteList.insert(L"\\360sd\\");
		m_usetRegistryNameWhiteList.insert(L"\\HP ProtectTools Security Manager\\");
		m_usetRegistryNameWhiteList.insert(L"\\QQPCMgr\\");
		m_usetRegistryNameWhiteList.insert(L"\\2345PCSafe\\");
		m_usetRegistryNameWhiteList.insert(L"\\2345SafeCenter\\");
		m_usetRegistryNameWhiteList.insert(L"\\Avira\\");
		m_usetRegistryNameWhiteList.insert(L"\\Avast Software\\");
		m_usetRegistryNameWhiteList.insert(L"\\Huorong\\");
		m_usetRegistryNameWhiteList.insert(L"\\Rising\\");
		m_usetRegistryNameWhiteList.insert(L"\\kingsoft antivirus\\");
		m_usetRegistryNameWhiteList.insert(L"\\Kaspersky Lab\\");
		m_usetRegistryNameWhiteList.insert(L"\\Trend Micro\\");
		m_usetRegistryNameWhiteList.insert(L"\\DriverGenius\\");
		m_usetRegistryNameWhiteList.insert(L"\\QQProtect\\");
		m_usetRegistryNameWhiteList.insert(L"Windows Defender");
		m_usetRegistryNameWhiteList.insert(L"OCloud");
		m_usetRegistryNameWhiteList.insert(L"\\IBM\\");
		m_usetRegistryNameWhiteList.insert(L"\\Ngep\\");
		m_usetRegistryNameWhiteList.insert(L"\\MagicShield\\");
		m_usetRegistryNameWhiteList.insert(L"\\WinSxS\\");
		m_usetRegistryNameWhiteList.insert(L"\\U8SOFT\\");
		m_usetRegistryNameWhiteList.insert(L"\\ZWSOFT\\");
	}
	
}

bool Filter::IsRansomBlackProcess(EventRecord* record)
{
    // cs
    //return true;
    if (!Setting::GetInstance().enable_ransom_detector())
        return false;

	auto _pid = record->get_process_id_();

//#ifdef ETW_EVENT_RECORD_TEST	
//	record->Record2csv("IsSuperWhiteListProcessEx");
//#endif
	if (IsSuperWhiteListProcessEx(_pid))
	{
//#ifdef ETW_EVENT_RECORD_TEST	
//		record->Record2csv("IsSuperWhiteListProcessEx true");
//#endif
		return false;
	}


	if (m_queueRansomSuffixWhiteListAddBuffer.size_approx() > 0)
	{
		std::set<String>().swap(m_setRansomSuffixWhiteList);
		std::set<DWORD>().swap(m_setRansomPidBlackList);
		while (m_queueRansomSuffixWhiteListAddBuffer.size_approx() > 0)
		{
			String suffix_name;
			if (m_queueRansomSuffixWhiteListAddBuffer.try_dequeue(suffix_name))
			{
				m_lockRansomSuffixData.ReadLock();
				m_setRansomSuffixWhiteList.insert(suffix_name);
				m_lockRansomSuffixData.ReadUnlock();
			}
		}
	}
	
	if (!record)
		return false;

	// 过滤需要的事件
	auto provider_id = record->get_event_identifier_().provider_id();
	auto opcode_id = record->get_event_identifier_().opcode();
	set< uint_32> opcode_output = { 1,2,3,64,67,68,71,70,72,65 };
	if (provider_id != ETWStackWalk && provider_id != ETWFileIo && provider_id != ETWProcess)
		return false;

	if (provider_id != ETWStackWalk && opcode_output.find(opcode_id) == opcode_output.end())
		return false;

	if (opcode_id == EM_ProcessEventOPC::ProcessEnd)
    {
        // 进程结束移除黑名单，可能后续子进程加入不了黑名单
        erase_ransom_process_id_black_list(record->GetDataParameter(parameter_index_enum::ProcessId));
        return true;	// 进程事件全发送至ransom
    }
	if (opcode_id == EM_ProcessEventOPC::ProcessStart || opcode_id == EM_ProcessEventOPC::ProcessDCStart)
	{
//#ifdef ETW_EVENT_RECORD_TEST	
//		record->Record2csv("IsRansomBlackProcess");
//#endif
		auto m_dwProcessId = record->GetDataParameter(parameter_index_enum::ProcessId);
		auto parentId = record->GetDataParameter(parameter_index_enum::ParentId);
		
		if (Filter::query_ransom_process_id_black_list(parentId))
		{
			Filter::insert_ransom_process_id_black_list(m_dwProcessId);
			WriteLog4cPlus(INFO_LEVEL, L"AddRansomBlackProcess process_id_ %d", m_dwProcessId);
		}
		return true;	// 进程事件全发送至ransom
	}	

	auto pid = record->get_process_id_();
	if (pid == 4)
		return false;

	// 针对ransom检测时不过滤 explorer，避免注入攻击
	if (!m_bCurrentRansomDetector && pid == m_dwExplorerPid)
		return false;

	if (Filter::query_ransom_process_id_black_list(pid))
		return true;

	do 
	{
		auto openpath = record->GetStringParameter(parameter_index_enum::OpenPath);
		auto filename = record->GetStringParameter(parameter_index_enum::FileName);
		const wstring& pepath = ToolFunctions::GetDirectoryfromPath(Filter::QurFullPath(pid));
		if (!pepath.empty())
		{
			if (!filename.empty() && filename.find(pepath) != wstring::npos)
				return false;

			if (!openpath.empty() && openpath.find(pepath) != wstring::npos)
				return false;
		}

		if (filename.length() > 0)
		{
			if (Filter::query_ransom_dir_white_list(filename))
			{	
				WriteLog4cPlus(INFO_LEVEL, L"query_ransom_dir_white_list opcode_id: %d,useles: %d, FileName: %s", opcode_id, record->isUseless(), filename.c_str());
				break;
			}
          
			size_t end = filename.find_last_of('.');
			if (end != string::npos)
			{
				auto suffix = ToolFunctions::WStringToString(filename.substr(end + 1)) ;//获取文件后缀
				if (suffix != "" && Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				{
					WriteLog4cPlus(INFO_LEVEL, L"query_ransom_suffix_white_list opcode_id: %d,useles: %d, FileName: %s", opcode_id, record->isUseless(), filename.c_str());
					break;
				}
			}
			
		}

		if (openpath.length() > 0)
		{
			if (Filter::query_ransom_dir_white_list(openpath))
			{
				WriteLog4cPlus(INFO_LEVEL, L"query_ransom_dir_white_list opcode_id: %d,useles: %d, FileName: %s", opcode_id, record->isUseless(), openpath.c_str());
				break;
			}

			size_t end = openpath.find_last_of('.');
			if (end != string::npos)
			{
				auto suffix = ToolFunctions::WStringToString(openpath.substr(end + 1));//获取文件后缀				
				if (suffix != "" && Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				{
					WriteLog4cPlus(INFO_LEVEL, L"query_ransom_suffix_white_list opcode_id: %d,useles: %d, FileName: %s", opcode_id, record->isUseless(), openpath.c_str());
					break;
				}
			}
		}

		return false;
	} while (0);

	Filter::insert_ransom_process_id_black_list(pid);				// 添加进程进黑名单
	WriteLog4cPlus(INFO_LEVEL, L"AddRansomBlackProcess parent process_id_ %d", pid);
    /* 不添加父进程所有子进程进队列，后续看检测情况
	for each (auto var in processid_parentid_map)
	{		
		if (var.second == pid)
		{
			if (var.first == _explorer_pid || var.first == 4 || var.first <= 0)
				continue;
			Filter::insert_ransom_process_id_black_list(var.first);	// 添加进程子进程进黑名单
		}		
	}
	*/
	return true;
}

//not used
//void Filter::insert_systemcall_name_list(std::string temp)
//{
//	m_setSignatureSystemcallNameList.insert(temp);
//}

void Filter::SignatureFileFilter()
{
	std::vector<std::string> files_path;
	std::vector<std::string> files_name;
	getFiles(m_strSignatureFilePath, files_path, files_name);

	//necessary event
	EventIdentifier temp_event_identifier;
	//process start
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessStart);
	temp_event_identifier.provider_id(ETWProcess);
	InsertEventIdentifier(temp_event_identifier);
	//process end
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessEnd);
	InsertEventIdentifier(temp_event_identifier);
	//process dcstart
	temp_event_identifier.opcode(EM_ProcessEventOPC::ProcessDCStart);
	InsertEventIdentifier(temp_event_identifier);
	//thread start
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadStart);
	temp_event_identifier.provider_id(ETWThread);
	InsertEventIdentifier(temp_event_identifier);
	//thread end
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadEnd);
	InsertEventIdentifier(temp_event_identifier);
	//thread dcstart
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadDCStart);
	InsertEventIdentifier(temp_event_identifier);
	//cswitch
	temp_event_identifier.opcode(EM_ThreadEventOPC::ThreadContextSwitch);
	InsertEventIdentifier(temp_event_identifier);

	for (std::vector<std::string>::iterator ix = files_path.begin(); ix != files_path.end(); ix++)
	{
		std::fstream infile(*ix, std::ios::in);
		std::string line;
		while (getline(infile, line))
		{
			if (line.find("@") != -1)
			{
				std::istringstream signature_line(line);
				std::string temp;
				signature_line >> temp;
				temp.erase(temp.begin());
				if (temp == "PerfInfoSysClEnter")
				{
					std::string temp_systemcall;
					signature_line >> temp_systemcall >> temp_systemcall;
					temp_systemcall.erase(0, 11);
					size_t pos = temp_systemcall.find('\"');
					temp_systemcall.erase(pos, 2);
					if (m_setSignatureSystemcallNameList.find(temp_systemcall) == m_setSignatureSystemcallNameList.end()) m_setSignatureSystemcallNameList.insert(temp_systemcall);
					//for (std::set<std::string>::iterator ix = systemcall_name_list.begin(); ix != systemcall_name_list.end(); ix++){
					//	if ((*ix).find(temp_systemcall)!=-1 && (signature_systemcall_name_list.find(*ix) == signature_systemcall_name_list.end())){
					//		signature_systemcall_name_list.insert(*ix);
					//		break;
					//	}
					//}
				}
				for (std::set<EventIdentifier>::iterator ix = m_setEventIdList.begin(); ix != m_setEventIdList.end(); ix++)
				{
					if (ix->event_name().find(temp) != string::npos && (m_setSignatureEventList.find(*ix) == m_setSignatureEventList.end()))
					{
						m_setSignatureEventList.insert(*ix);
						break;
					}
				}
			}
		}
		infile.close();
		infile.clear();
	}

	bool registry_flag_ = false;
	bool fileio_flag_ = false;
	bool alpc_flag_ = false;

	for (std::set<EventIdentifier>::iterator ix = m_setSignatureEventList.begin(); ix != m_setSignatureEventList.end(); ix++) 
	{
		if (ix->provider_id() == ETWALPC) alpc_flag_ = true;
		if (ix->provider_id() == ETWFileIo) fileio_flag_ = true;
		if (ix->provider_id() == ETWRegistry) registry_flag_ = true;
	}

	if (alpc_flag_) 
	{
		temp_event_identifier.opcode(EM_AlpcEventOPC::AlpcSendEvent);
		temp_event_identifier.provider_id(ETWALPC);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_AlpcEventOPC::ApcReceiveEvent);
		InsertEventIdentifier(temp_event_identifier);
	}

	if (fileio_flag_) 
	{
		temp_event_identifier.opcode(EM_FileioEventOPC::FileioFileCreateEvent);
		temp_event_identifier.provider_id(ETWFileIo);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_FileioEventOPC::FileioCreateEvent);
		InsertEventIdentifier(temp_event_identifier);
	}

	if (registry_flag_) {
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryCreate);
		temp_event_identifier.provider_id(ETWRegistry);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryKCBCreate);
		InsertEventIdentifier(temp_event_identifier);
		temp_event_identifier.opcode(EM_RegistryEventOPC::RegistryOpen);
		InsertEventIdentifier(temp_event_identifier);
	}
	m_setEventIdList.swap(m_setSignatureEventList);
}

void Filter::InitSystemcallEventList()
{
	std::fstream infile(addressmap_file, std::ios::in);
	std::string systemcall_name, systemcall_address;
	while (infile >> systemcall_name >> systemcall_address)
	{
		if (m_setSignatureSystemcallNameList.find(systemcall_name) != m_setSignatureSystemcallNameList.end())
		{
			m_setSystemcallAddressList.insert(atoi(systemcall_address.c_str()));
		}
	}
}
//not used
//void Filter::set_systemcall_list(std::string infile_name)
//{
//	std::fstream infile(infile_name, std::ios::in);
//	std::string systemcalll_name;
//	while (infile >> systemcalll_name){
//		systemcall_name_list.insert(systemcalll_name);
//	}
//}

bool Filter::QuerySystemcallName(std::string& systemcall_name)
{
//	std::string temp_systemcall_name;
//	Wchar_tToString(temp_systemcall_name, systemcall_name);
	if (m_setSignatureSystemcallNameList.size() == 0) return true;
	if (m_setSignatureSystemcallNameList.count(systemcall_name)) return true;
	return false;
}

