#pragma once

#include <set>
#include <vector>
#include <string>
#include "setting.h"
#include "event_identifier.h"
#include "event_record.h"
#include "event_record_pruner.h"
#include "concurrentqueue.h"

struct ProcessFilterData
{
	DWORD process_id;
	String file_path;
	String file_name;
	EM_CertificateResult certificate_result;
};
using ProcessFilterDataMap = std::unordered_map<DWORD, ProcessFilterData*>;

const int KProviderSize = 11;
const int KOpcodeSize = 256;
const std::string addressmap_file = "addressmap";
void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname);

class Filter
{
	SINGLETON_DEFINITION(Filter);

public:
	void Init();
    void LogCacheSize();
	bool FilterBeforeRecInstance(uint_32 provider_id, int_32 opcode, DWORD process_id);
	bool FilterAfterRecInstance(EventRecord* rec);
	bool FilterRegRecInstance(EventRecord* rec);
	bool IsSuperWhiteListProcess(DWORD pid);

	bool IsWhite(_In_ CONST std::wstring& wstrPath);
    // add by zxw on 20200724
    bool IsSuperWhiteListProcessEx(DWORD pid);
	// add by zxw on 20191029 是否特权pid进程
	bool IsPrivilegeProcess(DWORD pid);
	// 设置本机IP,如果有更新返回true否则false
	bool SetLoclaIPbyEventRecord(EventRecordTcpip* rec);
	// 获取本机IP
	std::string GetLocalIP();
	//
	// 添加目录白名单
	void AddRansomWhiteDir();
	// 添加勒索的注册表白名单
	void AddRansomRegistryWhiteList();
	bool IsRansomBlackProcess(EventRecord* record);
	//not used
	//static void insert_systemcall_name_list(std::string);
	static EventRecord* APIFilter(EventRecord* record);
	static bool FilterAfterParseRecord(EventRecord* record);

	// 针对勒索的注册表
	static void insert_registry_pid_white_list(DWORD process_id,const std::wstring& file_name)
	{
		if (m_setRegistryPidWhiteList.find(process_id) != m_setRegistryPidWhiteList.end()) return;
		for (wstring reg : m_usetRegistryNameWhiteList)
		{
			if (wcsstr(reg.c_str(), file_name.c_str()) != nullptr) 
			{
				m_setRegistryPidWhiteList.insert(process_id);
			}
		}
	}

	static bool query_registry_pid_white_list(DWORD process_id)
	{
		if (m_setRegistryPidWhiteList.find(process_id) != m_setRegistryPidWhiteList.end()) return true; else return false;
	}

	static void remove_registry_pid_white_list(DWORD process_id)
	{
		m_setRegistryPidWhiteList.erase(process_id);
	}

	static void insert_process_id_black_list(DWORD process_id) 
	{ 
		m_usetPidBlackList.insert(process_id); 
	}	
	static bool query_process_id_black_list(DWORD process_id) 
	{
		if (m_usetPidBlackList.count(process_id)) return true; else return false;
	}
	static void remove_process_id_black_list(DWORD process_id) 
	{
		m_usetPidBlackList.erase(process_id);
	}
	static void insert_process_id_white_list(DWORD process_id) 
	{
		m_usetPidWhiteList.insert(process_id);
	}
	static bool query_process_id_white_list(DWORD process_id) 
	{
		if (m_usetPidWhiteList.count(process_id)) return true; else return false;
	}
	static void insert_event_process_white_list(uint_32 provider_id, uint_32 opcode) 
	{
		m_usetEventProcessWhiteList.insert((uint_64)provider_id * 100 + opcode);
	}
	//not used
	//static void insert_event_output_white_list(EventIdentifier event_id) 
	//{
	//	event_output_white_list.insert(event_id);
	//}
	static void insert_api_name_white_list(std::string api_name)
	{
		m_usetApiNameWhiteList.insert(api_name);
	}

	// add by zxw on 20191119
	static void insert_ransom_dir_white_list(std::wstring ransom_dir)
	{
		if (!m_setRansomDirWhiteList.count(ransom_dir))
			m_setRansomDirWhiteList.insert(ransom_dir);
	}
	static bool query_ransom_dir_white_list(std::wstring ransom_dir)
	{
		for each (auto var in m_setRansomDirWhiteList)
		{
			if (ransom_dir.find(var) != std::wstring::npos)
			{
				return true;
			}			
		}
		return false;
	}
	//not used
	//static void insert_ransom_suffix_white_list(std::string suffix)
	//{
	//	if (!m_setRansomSuffixWhiteList.count(suffix))
	//		m_setRansomSuffixWhiteList.insert(suffix);
	//}
	static bool query_ransom_suffix_white_list(std::string suffix)
	{
        if (m_setRansomSuffixWhiteList.size() <= 0 || suffix.length() <= 0)
        {
            return false;
        }

		for each (auto var in m_setRansomSuffixWhiteList)
		{
			if (suffix.find(var) != std::string::npos)
			{
				return true;
			}
		}

		return false;
	}
	static void insert_ransom_process_id_black_list(DWORD process_id)
	{
		if (m_setRansomPidBlackList.find(process_id) == m_setRansomPidBlackList.end())
		{
			m_setRansomPidBlackList.insert(process_id);
		}		
	}
	static bool query_ransom_process_id_black_list(DWORD process_id)
	{
		if (m_setRansomPidBlackList.count(process_id)) return true; else return false;
	}
    static void erase_ransom_process_id_black_list(DWORD process_id)
    {
        if (m_setRansomPidBlackList.find(process_id) != m_setRansomPidBlackList.end())
        {
            m_setRansomPidBlackList.erase(process_id);
        }
    }

    // add by zxw on 20200811
    static void insert_tid_pruner_black_list(DWORD thread_id) {
        if (m_usetTidPrunerBlackList.find(thread_id) == m_usetTidPrunerBlackList.end()) {
            m_usetTidPrunerBlackList.insert(thread_id);
        }
    }
    static bool query_tid_pruner_black_list(DWORD thread_id) {
        if (m_usetTidPrunerBlackList.count(thread_id)) return true; else return false;
    }
    static void erase_tid_pruner_black_list(DWORD thread_id) {
        if (m_usetTidPrunerBlackList.find(thread_id) != m_usetTidPrunerBlackList.end()) {
            m_usetTidPrunerBlackList.erase(thread_id);
        }
    }
    static int get_tid_pruner_black_list_size() {
        return (int)m_usetTidPrunerBlackList.size();
    }
    
    static void insert_pid_pruner_black_list(DWORD process_id) {
        if (!m_usetPidPrunerBlackList.count(process_id)) {
            m_usetPidPrunerBlackList.insert(process_id);
        }
    }
    static bool query_pid_pruner_black_list(DWORD process_id) {
        if (m_usetPidPrunerBlackList.count(process_id)) return true; else return false;
    }
    static void erase_pid_pruner_black_list(DWORD process_id) {
        if (m_usetPidPrunerBlackList.count(process_id)) {
            m_usetPidPrunerBlackList.erase(process_id);
        }
    }
    static int get_pid_pruner_black_list_size() {
        return (int)m_usetPidPrunerBlackList.size();
    }

	static void DelFullPath(DWORD pid)
	{
		m_umapPid2FullPath.erase(pid);
	}

	static wstring QurFullPath(DWORD pid)
	{
		auto iter = m_umapPid2FullPath.find(pid);
		if (iter != m_umapPid2FullPath.end())
			return iter->second;
		else return L"";
	}

	static void AddFullPath(DWORD pid, const wstring& path)
	{
		m_umapPid2FullPath[pid] = path;
	}


    static void insert_pid_pruner_white_list(DWORD process_id) {
        if (m_usetPidPrunerWhiteList.find(process_id) == m_usetPidPrunerWhiteList.end()) {
            m_usetPidPrunerWhiteList.insert(process_id);
        }
    }
    static bool query_pid_pruner_white_list(DWORD process_id) {
        if (m_usetPidPrunerWhiteList.count(process_id)) return true; else return false;
    }
    static void erase_pid_pruner_white_list(DWORD process_id) {
        if (m_usetPidPrunerWhiteList.find(process_id) != m_usetPidPrunerWhiteList.end()) {
            m_usetPidPrunerWhiteList.erase(process_id);
        }
    }
    static int get_pid_pruner_white_list() {
        return (int)m_usetPidPrunerWhiteList.size();
    }
    /*
	// 
	static void insert_processid_parentid_map(DWORD process_id, DWORD parent_id)
	{
		processid_parentid_map.insert(std::pair<DWORD, DWORD>(process_id, parent_id));
	}
	static void erase_processid_parentid_map(DWORD process_id)
	{
		if (processid_parentid_map.count(process_id) != 0)
		{
			processid_parentid_map.erase(process_id);
		}		
	}
	// 
    */
	static bool isSystemCallNeeded(int);
	static bool isEventNeeded(EventIdentifier);
	static bool AddEvent(EventIdentifier);
	static bool AddSystemCall(int);
	static size_t QueryEventListSize();
	static size_t QuerySystemCallListSize();
    static String GetEventName(EventIdentifier ID);
	static bool DelEvent(EventIdentifier);
	static bool DelSystemCall(int);
	//not used
	//static void set_systemcall_list(std::string);
	static void SignatureFileFilter();
	static bool QuerySystemcallName(std::string&);
	//int get_enableflag();
	//void CreatEnableFlag();
	static void InitSystemcallEventList();
	static void InsetUselessAPIList(std::wstring);
	static bool QueryUselessAPIList(std::wstring);
	static void set_signature_file_path(std::string);

	void OnExeImageLoad(DWORD pid, const String& file_path);
	void OnExeCertificateResult(DWORD pid, EM_CertificateResult result);
	void OnProcessEnd(DWORD pid);
    // add by zxw on 20200811
    void OnProcessStart(EventRecordProcess* rec);
    void OnThreadEnd(DWORD tid, DWORD pid);
    void OnThreadStart(EventRecordThread* rec);
    void OnPhfDetectorResult(DWORD pid);

	bool IsProcessCertificate(DWORD pid) const;

	void InitSuperWhiteList(const STRING_VECTOR& list_init);
	void AddSuperWhiteList(const STRING_VECTOR& list_add);
	void RemoveSuperWhiteList(const STRING_VECTOR& list_remove);
	void ChangeSuperWhiteList(const String& file_name_s, const String& file_name_d);
	// add by zxw on 20191206
	//void AddRansomSuffixWhiteList(const STRING_VECTOR& list_add);
    void AddRansomSuffixWhiteList(const STRING_VECTOR& list_add, int is_terminate);
    void UpdateRansomDetector();
    bool GetRansomDetector() { return m_bCurrentRansomDetector; }
    //
    bool GetRansomTerminate() { return m_bRanssomIsTerminate||Setting::GetInstance().enable_ransom_terminate(); }
    // add by zxw on 20201021
    void RuleMatchSwitch(std::string rule_match);
    // add by zxw on 20210508
    void AddCertificateWhiteListBuffer(const std::vector<SCertificateResult>& list_add);
    bool IsInCertificateWhiteList(std::string thumbPrint, std::string subjectname);
    void AddSurpCertificateWhiteListBuffer(DWORD pid);
    bool IsCertificateWhiteListProcess(DWORD pid);
       
	String GetProcessFileName(DWORD pid) const;

	void SetCollectorGear(CollectorGear gear);
	CollectorGear GetCollectorGear();
    
private:
	// if event is in this list, then it should be a useless API;
	static std::set<std::wstring> m_setUselessAPIList;
	// if event is not in this list, than it should not be pass to the parseEventRecord()
	static std::unordered_set<uint_64> m_usetEventProcessWhiteList;
	// if event is not in this list, than it should not be pass to output
	//not used
	//static std::set<EventIdentifier> event_output_white_list;
	static std::unordered_set<DWORD> m_usetPidBlackList;
	static std::unordered_set<DWORD> m_usetPidWhiteList;
	static std::unordered_set<std::string> m_usetApiNameWhiteList;
	static std::unordered_set<std::wstring> m_usetRegistryNameWhiteList;
	static std::set<DWORD> m_setRegistryPidWhiteList;
	//not used
	//static std::set<DWORD> registry_pid_black_list;  // Avoid repeated judgment
    static std::unordered_map<DWORD, std::unordered_set<DWORD>> m_umapParent2ChildPid;
    static std::unordered_map<DWORD, std::unordered_set<DWORD>> m_umapPid2Tid;
    static std::unordered_set<DWORD> m_usetTidPrunerBlackList;
    static std::unordered_set<DWORD> m_usetPidPrunerBlackList;
    static std::unordered_set<DWORD> m_usetPidPrunerWhiteList;
	static std::unordered_map<DWORD, std::wstring> m_umapPid2FullPath;
	//bool event_filter_list[KProviderSize][KOpcodeSize];
	//int provider_modulo_mapping_hash[KProviderSize];
	static std::set<int> m_setSystemcallAddressList;
	static std::set<EventIdentifier> m_setEventIdList;
	//not used
	//static std::set<std::string> systemcall_name_list;
	static std::set<std::string> m_setSignatureSystemcallNameList;
	static std::set<EventIdentifier> m_setSignatureEventList;
	static std::string m_strSignatureFilePath;
	static void InsertEventIdentifier(EventIdentifier);

	bool _FilterByGear(DWORD process_id, uint_32 provider_id) const;
	void _OnAddSuperWhiteList(const String& file_name);
	void _OnRemoveSuperWhiteList(const String& file_name);

	moodycamel::ConcurrentQueue<String> m_queueSuperWhiteListConfigAddBuffer;
	moodycamel::ConcurrentQueue<String> m_queueSuperWhiteListConfigRemoveBuffer;
	/*std::unordered_set<std::string>*/
	STRING_SET m_usetSuperWhiteListConfig;
    // mod by zxw on 20200525
	moodycamel::ConcurrentQueue<ProcessFilterData> m_queueSuperWhiteListWaitBuffer;
    //moodycamel::ConcurrentQueue<ProcessFilterData*> _super_white_list_wait_buffer;
	std::unordered_set<DWORD> m_usetSuperWhiteList;

	mutable RwLock m_lockProcessFilterData;
	/*std::unordered_map<DWORD, ProcessFilterData*>*/
	ProcessFilterDataMap m_umapProcessFilterData;

	CollectorGear m_emCurrentGear;
	// add by zxw on 20191029 添加特权pid特殊处理,获取本机IP
	DWORD m_dwPrivilegePid = 0;
	// add by zxw on 20191122 添加explorer pid特殊处理
	static DWORD m_dwExplorerPid;
    // add by zxw on 20200724 add autorunsc64.exe pid
    DWORD m_dwAutorunsc64Pid = 0;
    std::string m_strAutorunsc64Path;
	
	std::string m_strLocalIp;
	// add by zxw on 20191119 
    bool m_bCurrentRansomDetector;
	static std::set<std::wstring> m_setRansomDirWhiteList;		// 添加ransom目录白名单
	// add by zxw on 20191206 
	mutable RwLock m_lockRansomSuffixData;
	moodycamel::ConcurrentQueue<String> m_queueRansomSuffixWhiteListAddBuffer;
	static std::set<String> m_setRansomSuffixWhiteList;			// 添加ransom后缀白名单	
	static std::set<DWORD> m_setRansomPidBlackList;		// 检测进程黑名单
    //
    int m_bRanssomIsTerminate = 0;
	//static std::unordered_map<DWORD, DWORD> processid_parentid_map;
    // add by zxw on 20210508
    moodycamel::ConcurrentQueue<SCertificateResult> m_queueCertificateWhiteListAddBuffer;
    static std::set<SCertificateResult> m_setCertificateWhiteList;	// 添加企业证书白名单	

    moodycamel::ConcurrentQueue<DWORD> m_queueSuperCertificateWhiteListAddBuffer;
    std::unordered_set<DWORD> m_usetSuperCertificateWhiteList;
};

void getFiles(std::string path, std::vector<std::string>& files, std::vector<std::string> &ownname);
