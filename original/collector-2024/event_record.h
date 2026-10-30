#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-3-28
// Updated 2018-4-28

#include "parameter_index.h"
#include "event_identifier.h"
#include <Windows.h>
#include <evntrace.h>

#define EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE L""
#define EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE 0

class ParameterValue
{
public:
	ULONG64 d;
	std::wstring s;
	ParameterValue():d(0),s(L""){}
};

class EventRecord
{
    friend class EventRecordPruner;
	friend class EventRecordManager;
	friend class ExtraTraceSession;
	friend class Output;
	friend class OutputDb;
	friend class OutputKafka;
	friend class UnitTest;
	friend class OutputJson;
	friend class RecordQueue;
	friend class AvroSnappy;
    friend class public_json_interface;
//public:
//	static int constructor_num;
//	static int destruct_num;
public:
	EventRecord();
	EventRecord(PEVENT_RECORD raw_rec);

	virtual ~EventRecord();
	
	virtual void InitFrom(EventRecord* origin);
	virtual bool isUseless();
	virtual void InitParse();
	virtual int parse() = 0; //pure virtual function
	virtual bool Output();

	void copy(EventRecord* origin);
	std::wstring GetStringParameter(parameter_index_enum);
	ULONG64 GetDataParameter(parameter_index_enum);
	bool SetParameter(parameter_index_enum, std::wstring);
	bool SetParameter(parameter_index_enum, ULONG64);
	int get_process_id_();
	int get_thread_id_();
	//unsigned long long get_time_stamp_() { return time_stamp_; }
	ULONG64 get_time_stamp_() { return m_ulTimeStamp; }
	std::string& get_callstack_() { return m_strCallstack; }
	vector<int>& get_vec_callstack_() {
		return m_vecCallstack;
	}
	EventIdentifier& get_event_identifier_();
	void set_event_identifier_(EventIdentifier);
	void SetProcessTcpPreEventRecord(EventRecord* temp) { m_umapProcessTcpPreEventrecord[m_dwProcessId] = temp->get_thread_id_(); }
	void QPCtimeToSystime();
	//用于初始化静态成员变量
	void init_timecal();

	static void clear_process_tcp_pre_eventrecord() { m_umapProcessTcpPreEventrecord.clear(); }
	static void SetRunningModeFlag(char flag) { m_cRunningModeFlag = flag; }
    static bool query_process_id2process_name_map_(DWORD pid) { 
        if (m_umapPid2ProcessName.count(pid)) return true; else return false;
    }
    static void update_process_id2network_time_map_(DWORD pid, ULONG64 ulTime);
    static ULONG64 get_process_network_timestamp(DWORD pid);
	static BOOL m_bInit;

	//first start time 
	static LARGE_INTEGER m_liFrequency;
	static ULONG64 m_ulStartEtwtime;
	static ULONG64 m_nStartSystemtime;

#ifdef ETW_EVENT_RECORD_TEST	
	VOID Record2csv(string strExData)
	{

		bool bAdd = true;
		stringstream ss;
		string output;
		ss << strExData << ",";
		ss << m_ulTimeStamp << ",";
		ss << m_nProcessorId << ",";
		ss << m_dwProcessId << ",";
		ss << m_dwThreadId << ",";
		ss << m_eventIdentifier.event_name() << ",";
		ss << m_eventIdentifier.opcode() << ",";
		ss << m_eventIdentifier.provider_id() << ",";
		ss << m_strCallstack << ",";
		ss << m_strEventName << ",";
		ss << m_bUseless << ",";
		for (auto i :m_vctParameterList)
		{
			std::string strT;
			if (!i.s.empty())
				strT = CPykMgrTemplate<CP_ACP>(i.s.c_str());
			ss << i.d << "|" << strT << ";";
		}
		ss << ",";
		
		output = ss.str();
		if (bAdd)
			g_thCRC.AddLine("EventRecord", output.c_str());
	}
#endif

protected:
	static std::unordered_map<DWORD, DWORD> m_umapTid2Pid;
	static std::vector<DWORD> m_vctProcessorId2TidList;
	static std::unordered_map<DWORD, std::wstring> m_umapPid2ProcessName;
    // pid&network timestamp
    static std::unordered_map<DWORD, ULONG64> m_umapPid2NetworkTime;
	static std::unordered_map<DWORD, DWORD> m_umapProcessTcpPreEventrecord;
	// running mode: "realtime" or "writelogfile" or "parselogfile"
	static char m_cRunningModeFlag;

	ULONG64 m_ulTimeStamp;
	short m_nProcessorId;
	DWORD m_dwProcessId;
	DWORD m_dwThreadId;
	EventIdentifier m_eventIdentifier;
	std::string m_strCallstack;
	vector<int> m_vecCallstack;
	std::string m_strEventName;
	bool m_bUseless;
	std::vector<ParameterValue> m_vctParameterList;
	GUID m_dGuid;
};

using EventRecordVector = std::vector<EventRecord*>;
using EventRecordList = std::list<EventRecord*>;
