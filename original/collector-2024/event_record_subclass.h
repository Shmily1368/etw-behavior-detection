#pragma once

// Writed by Chunlin(chunlinxiong@foxmail.com)
// Created 2018-04-02
// Updated 2018-04-03

#include "event_record.h"
#include "map_auto_cleanup.h"
#include "macro_detector.h"
#include "get_systemcontext.h"
#include <list>
#include <functional> 
#include <windows.h>
#include "cert_analyzer.h"

class EventRecordPerfInfo : public EventRecord
{
public:
	EventRecordPerfInfo(PEVENT_RECORD raw_rec);
	~EventRecordPerfInfo();

	void InitParse() override;
	int parse() override;
	virtual bool Output() override;
};

class EventRecordUnknown : public EventRecord
{
public:
	EventRecordUnknown();
	~EventRecordUnknown();

	int parse() 
	{
		m_bUseless = true;
		return 0; 
	}
};

class EventRecordAlpc : public EventRecord
{
public:
	EventRecordAlpc(PEVENT_RECORD raw_rec);
	EventRecordAlpc(DWORD input_thread_id, DWORD input_process_id, ULONG64 time_stamp);
	~EventRecordAlpc();

	int parse() override;
	struct AlpcMessage {
		int message_id;
		int process_id;
		int thread_id;
		AlpcMessage() {
			process_id = 0;
			message_id = 0;
			thread_id = 0;
		}
	};
	EventRecord* get_correspond_send();

private:
	static std::list<AlpcMessage> send_message_list_;

	class messageid_to_find :public std::unary_function<AlpcMessage, bool>
	{
	private:
		int name;
	public:
		explicit messageid_to_find(int iname) :name(iname) {}
		bool operator()(const AlpcMessage& alpc_message)
		{
			return (alpc_message.message_id == name);
		}
	};
};

class EventRecordThread : public EventRecord
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	EventRecordThread(PEVENT_RECORD raw_rec);
	~EventRecordThread();

protected:
	DWORD _owner_pid;
};

class EventRecordDiskio : public EventRecord
{
public:
	EventRecordDiskio(PEVENT_RECORD raw_rec);
	~EventRecordDiskio();
	void InitParse() override;
	int parse() override;
};

struct FileIoInfo 
{
	int used;
	std::wstring file_name;
};

class EventRecordFileioSuffix
{
public:
	EventRecordFileioSuffix() {}
	~EventRecordFileioSuffix() {}

	static std::string GetSuffix(std::string strIn)
	{
		std::string strSuffix;
		size_t end = strIn.find_last_of(L'.');
		if (end != string::npos)
			strSuffix = strIn.substr(end + 1);//获取文件后缀
		return strSuffix;
	}

	static int GetEnumFromSuffix(std::string strSuffix)
	{
		if (m_setSuffixList.count(strSuffix) == 0)
			return 0;
		for (auto i : m_vctEnum2SuffixList)
		{
			if (i.second.count(strSuffix) != 0)
				return i.first;
		}
		return 0;
	}

	static void InitSuffixList()
	{
		for (auto i: m_vctEnum2SuffixList)
			m_setSuffixList.insert(i.second.begin(),i.second.end());
	}

	static std::vector<std::pair<int, std::set<std::string>>> m_vctEnum2SuffixList;
	static std::set<std::string> m_setSuffixList;

	void SetSuffix(std::string strSet) { m_strSuffix = strSet; }
	std::string GetSuffix() { return m_strSuffix; }
private:
	std::string m_strSuffix;
	int m_nSuffixEnum = 0;
};

class EventRecordRegistryPathClassification
{
private:
	static std::vector<std::pair<int, std::string>> m_vctEnum2RegistryPath;
	/*0-create 1-delete 2-query 3-set*/
	using RegistryUnitOperations = std::tuple<int, int, int, int>;
	static std::mutex m_mutexPid2RegOptlist;
	static std::unordered_map<DWORD, std::shared_ptr<std::vector<RegistryUnitOperations>>>
		m_umapPid2RegOptlist;
	static int g_nMaxRegistryPathSize;
public:
	EventRecordRegistryPathClassification() {}
	~EventRecordRegistryPathClassification() {}

	enum RegistryOperationType
	{
		ROT_Create = 0,
		ROT_Delete = 1,
		ROT_Query,
		ROT_Set,
	};

	//注册表分类导致cpu使用率升高
	static void InsertRegistry(DWORD dwPid, std::string strReg, RegistryOperationType nType)
	{
		std::lock_guard<std::mutex> lk(m_mutexPid2RegOptlist);
		if (!m_umapPid2RegOptlist.count(dwPid))
			m_umapPid2RegOptlist[dwPid] =std::make_shared<std::vector<RegistryUnitOperations>>(g_nMaxRegistryPathSize);

		auto ptr = m_umapPid2RegOptlist[dwPid];

		int nEnum = 0;
		for (auto i : m_vctEnum2RegistryPath)
		{
			if (strReg.find(i.second)!=strReg.npos)
				nEnum = i.first;
		}
		//auto pTuple = &(*ptr)[nEnum];
		switch (nType)
		{
		case EventRecordRegistryPathClassification::ROT_Create:
			(std::get<0>((*ptr)[nEnum]))++;
			break;
		case EventRecordRegistryPathClassification::ROT_Delete:
			(std::get<1>((*ptr)[nEnum]))++;
			break;
		case EventRecordRegistryPathClassification::ROT_Query:
			(std::get<2>((*ptr)[nEnum]))++;
			break;
		case EventRecordRegistryPathClassification::ROT_Set:
			(std::get<3>((*ptr)[nEnum]))++;
			break;
		default:
			break;
		}
	}
	static std::shared_ptr<std::vector<RegistryUnitOperations>> GetAndRemoveRegistryInfoByPid(DWORD dwPid)
	{
		std::lock_guard<std::mutex> lk(m_mutexPid2RegOptlist);
		std::shared_ptr<std::vector<RegistryUnitOperations>> pvctRet = std::make_shared<std::vector<RegistryUnitOperations>>(g_nMaxRegistryPathSize);
		if (m_umapPid2RegOptlist.count(dwPid))
		{
			//auto ptr = m_umapPid2RegOptlist[dwPid];
			pvctRet.swap(m_umapPid2RegOptlist[dwPid]);
		}			
		return pvctRet;
	}
private:

};

class EventRecordFileio : public EventRecord
	,public EventRecordFileioSuffix
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	bool Output() override;
	EventRecord* renameCache();
	void GetLastWrittenInterval();
	inline const std::wstring& GetFileName() const { return _file_name; }
	EventRecordFileio(PEVENT_RECORD raw_rec);
	EventRecordFileio();
	~EventRecordFileio();
	//static Unordered_map file_context;  // need to define its hash function
	static std::unordered_map<ULONG64,std::wstring> file_context;

	static std::unordered_map<ULONG64, FileIoInfo> file_key2file_info_map;
	static std::unordered_map<ULONG64, FileIoInfo> file_object2file_info_map;
	static std::unordered_map<ULONG64, EventRecordFileio*> fileiorename_cache_map;

	static long EventRecordFileio::parse_num;
	static ULONG64 collector_pid;

private:
	void _ParseFileName();
	void _TryProcessMacro();
	void _OnConvertPathError();
    void _UploadFile();
    void AddIsDownloadParameter();
private:
	std::wstring _file_name;
	bool _force_convert_path;
};

class EventRecordRegistry : public EventRecord
{
public:
	EventRecordRegistry(PEVENT_RECORD raw_rec);
	~EventRecordRegistry();
	int parse() override;
    bool Output() override;
	static std::vector<bool> isroot_match;
private:    
    void ParseRegistryKCBCreate();
    void ParseRegistryCreate();
    void ParseRegistryOpen();
    void ParseRegistrySetValue();
    void ParseRegistryClose(); 
    void ParseRegistryDelete();
    void ParseRegistryDeleteValue();
    void ParseRegistryQuery();
public:
	//static MapAutoCleanup<ULONG64,std::wstring>key_handle2key_name_map;
    // mod by zxw on 20200512 key=handle+pid
    static MapAutoCleanup<std::wstring, std::wstring> key_handle2key_name_map;
	static std::unordered_map<DWORD, std::wstring> thread2_keyname;  // save TID,key name not have corresponding keyhandle yet

    static wstring s_openKeyName;
    static wstring s_openKeyHandle; 
    static wstring s_createKeyName;
    static wstring s_createKeyHandle;
    static wstring s_createKey;
};

class EventRecordProcess : public EventRecord
{
public:
	void InitParse() override;
	int parse() override;
	bool Output() override;
    EventRecordProcess();
	EventRecordProcess(PEVENT_RECORD raw_rec);
	~EventRecordProcess();
private:
	bool HasUnicodeName(const std::wstring& command);
	std::wstring GetProcessName(const std::wstring& command);
};

class EventRecordTcpip : public EventRecord
{
public:
	EventRecordTcpip(PEVENT_RECORD raw_rec);
    EventRecordTcpip();
	~EventRecordTcpip();
	void InitParse() override;
	int parse() override;
	bool Output() override;
};

class EventRecordUdpip : public EventRecord
{
public:
	EventRecordUdpip(PEVENT_RECORD raw_rec);
    EventRecordUdpip();
	~EventRecordUdpip();
	void InitParse() override;
	int parse() override;
	bool Output() override;
};

class EventRecordImage : public EventRecord
{
public:
	virtual void InitFrom(EventRecord* origin) override;
	void InitParse() override;
	int parse() override;
	bool Output() override;
	void certificate();
	bool is_ransom_black(const std::wstring& module_name) const;
    void CheckCertificate(std::list<SIGN_NODE_INFO> SignChain);
	EventRecordImage();
	EventRecordImage(PEVENT_RECORD raw_rec);
	~EventRecordImage();

private:
	void _OnConvertPathError();

private:
	static STRING_SET _dll_need_rva_set;
	static STRING_SET _dll_need_rva_ransom_set;
	bool m_bNeedRva;
	
	bool _force_convert_path;
	bool _convert_path_succ;
};

class EventRecordVisibleWindow : public EventRecord
{
public:
	EventRecordVisibleWindow();
	~EventRecordVisibleWindow();
	int parse() override { return 1; };
};

class EventRecordMouse : public EventRecord
{
public:
	EventRecordMouse();
	~EventRecordMouse();
	int parse() override { return 1; };
};

class EventRecordKeyBoard : public EventRecord
{
public:
	EventRecordKeyBoard();
	~EventRecordKeyBoard();
	int parse() override { return 1; };
};

class EventMacroResult : public EventRecord
{
public:
	EventMacroResult(EventRecordFileio* rec_file_io);
	~EventMacroResult();

	virtual int parse() override;
	virtual bool Output() override;

private:
	static uint_32 _parse_counter;
	static unordered_map<std::wstring, int_32> _detected_macro_file_record_map;
	EM_FileioEventOPC _original_opcode;
	std::wstring _original_pname;

	EM_MarcoDetectResult _result;
	std::wstring _file_path;
	STRING_VECTOR _macro_contents;
};

class EventRemovableDevice : public EventRecord
{
public:
	EventRemovableDevice();
	~EventRemovableDevice();
	int parse() override { return 1; };
};

class EventIpconfig : public EventRecord
{
public:
	EventIpconfig();
	~EventIpconfig();
	int parse() override { return 1; };
};

class EventHealthCheck : public EventRecord
{
public:
	EventHealthCheck(const string& unique_id);
	~EventHealthCheck();

	int parse() override { return 1; }
};

class EventInitSignal : public EventRecord
{
public:
	EventInitSignal();
	~EventInitSignal();

	int parse() override { return 1; }
};

class EventAutorunInfo : public EventRecord
{
public:
	EventAutorunInfo(const String& file_path);
	virtual ~EventAutorunInfo() override;

	virtual int parse() override { return 1; }
};

class EventRansomCheck : public EventRecord{
public:
	EventRansomCheck();
	virtual ~EventRansomCheck() override;

	virtual int parse() override { return 1; }
};

class EventRansomTerminate : public EventRecord {
public:
	EventRansomTerminate();
	virtual ~EventRansomTerminate() override;

	virtual int parse() override { return 1; }
};

class EventPowershellCheck : public EventRecord {
public:
	EventPowershellCheck();
	virtual ~EventPowershellCheck() override;

	virtual int parse() override { return 1; }
};

class EventZoneIdentifier : public EventRecord {
public:
    EventZoneIdentifier();
    virtual ~EventZoneIdentifier() override;

    virtual int parse() override { return 1; }
};
class EventDriverLoaded : public EventRecord {
public:
    EventDriverLoaded();
    virtual ~EventDriverLoaded() override;

    virtual int parse() override { return 1; }
};
class EventProcessAccess : public EventRecord {
public:
    EventProcessAccess();
    virtual ~EventProcessAccess() override;

    virtual int parse() override { return 1; }
};
class EventHashInfo : public EventRecord {
public:
    EventHashInfo();
    virtual ~EventHashInfo() override;

    virtual int parse() override { return 1; }
};

class EventRecordStaticInit
{
public:
	static void InitEventRecordSubclassStatic()
	{
		EventRecordFileioSuffix::InitSuffixList();
	}
};