#pragma once

#include "event_record.h"
#include "event_record_callstack.h"
#include "event_record_subclass.h"
#include "spin_lock.h"

struct KeyloggerApiData
{
	DWORD process_id;
	DWORD thread_id;
	int_64 timestamp;
	String api_name;

	KeyloggerApiData(DWORD process_id_t, DWORD thread_id_t, int_64 timestamp_t, const String& api_name_t)
		: process_id(process_id_t), thread_id(thread_id_t), timestamp(timestamp_t), api_name(api_name_t)
	{

	}

};
using KeyloggerApiDataQueue = std::queue<KeyloggerApiData>;
using ThreadKeyloggerApiDataQueueMap = std::map<DWORD, KeyloggerApiDataQueue>;

using KeyloggerProcessSet = std::set<DWORD>;

class PhfDetector 
{
	SINGLETON_DEFINITION(PhfDetector);

public:
	PhfDetector() = default;
	~PhfDetector() = default;

	void Init();
	EventRecord* PushBack(EventRecordCallstack* event_record);
	void ProcessSystemCall(EventRecordPerfInfo* ev);

	void NotifyProcessStart(DWORD ppid, std::wstring imageFileName, ULONG64 timestamp);
	void TryDetectPhf();
	void NotifyProcessEnd(DWORD ppid, ULONG64 timestamp);
    void NotifyThreadEnd(DWORD ttid);
	void OutputDetectPhf();
	void ParseThread2ApisFullWithVec(EventRecordCallstack* event_record);
	bool isUselessApi(const string & api);
	void InitMLAPIFilter();
	bool isUselessCallstack(const vector<int> & callstack);
	int FindApiIndex(string api);
	bool isRepetitiveCallstack(const vector<int>& api, vector<int>& precallstack);

	void ActiveDetectPhfFlag() { m_bDetectPhfFlag = true; }

    static KeyloggerProcessSet m_setKeyloggerThreadCache;
   
private:
	int api_index_num = 0;
	ThreadKeyloggerApiDataQueueMap m_mapPid2KeyLoggerApiQueue; 
    ThreadKeyloggerApiDataQueueMap _thread_reflective_api_queue_map;
	bool m_bDetectPhfFlag = false;
private:
    std::unordered_map<DWORD, int_64> m_umapTid2Timestamp;
    void KeyloggerEraseMap(DWORD tid);
    bool KeyloggerPruner(DWORD tid, int_64 timestamp);
};