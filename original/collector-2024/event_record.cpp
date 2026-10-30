#include "stdafx.h"
#include "event_record.h"
#include "parameter_index.h"
#include "event_record_manager.h"
#include "init_collector.h"
#include "setting.h"
#include "thread_task_manager.h"

#define EPOCHFILETIME   (116444736000000000UL)

char EventRecord::m_cRunningModeFlag;

std::unordered_map<DWORD, DWORD> EventRecord::m_umapProcessTcpPreEventrecord;
BOOL  EventRecord::m_bInit = FALSE;
LARGE_INTEGER EventRecord::m_liFrequency;
ULONG64 EventRecord::m_ulStartEtwtime;
ULONG64 EventRecord::m_nStartSystemtime;

//int EventRecord::constructor_num = 0;
//int EventRecord::destruct_num = 0;
EventRecord::EventRecord()
{
	m_bUseless = false;
	OBJECT_MEMORY_MONITOR_CTOR(EventRecord);
	//constructor_num++;
}

EventRecord::EventRecord(PEVENT_RECORD raw_rec)
	: m_ulTimeStamp(raw_rec->EventHeader.TimeStamp.QuadPart)
	, m_nProcessorId(raw_rec->BufferContext.ProcessorNumber)
	, m_dwProcessId(raw_rec->EventHeader.ProcessId)
	, m_dwThreadId(raw_rec->EventHeader.ThreadId)
	, m_eventIdentifier(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Opcode)
	, m_strCallstack(EMPTY_STRING)
	, m_strEventName(EMPTY_STRING)
	, m_bUseless(false)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecord);
    if (!m_bInit)
        init_timecal();
}

EventRecord::~EventRecord()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecord);
	//destruct_num++;
}

bool EventRecord::isUseless()
{
	return m_bUseless;
}

void EventRecord::InitParse()
{

}

void EventRecord::copy(EventRecord *origin)
{
	*origin = *this;
	origin->m_vctParameterList.assign(m_vctParameterList.begin(), m_vctParameterList.end());
}

void EventRecord::InitFrom(EventRecord* origin)
{
	m_ulTimeStamp = origin->m_ulTimeStamp;
	m_nProcessorId = origin->m_nProcessorId;
	m_dwProcessId = origin->m_dwProcessId;
	m_dwThreadId = origin->m_dwThreadId;
	m_eventIdentifier = origin->m_eventIdentifier;
	m_strCallstack = origin->m_strCallstack;
	m_vecCallstack = origin->m_vecCallstack;
	m_strEventName = origin->m_strEventName;
	m_bUseless = origin->m_bUseless;
	std::copy(origin->m_vctParameterList.begin(), origin->m_vctParameterList.end(), std::back_inserter(m_vctParameterList));
}

wstring EventRecord::GetStringParameter(parameter_index_enum parameter_name)
{
	int parameter_postion = EventRecordManager::GetInstance().query_parameter_posistion(m_eventIdentifier, parameter_name);
	if (parameter_postion == -1 || parameter_postion >= m_vctParameterList.size()) {
		return EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE;
	}
	else {
		return m_vctParameterList[parameter_postion].s;
	}

	return EVENT_RECORD_DEFAULT_STRING_PARAMETER_VALUE;
}

ULONG64 EventRecord::GetDataParameter(parameter_index_enum parameter_name)
{
	int parameter_postion = EventRecordManager::GetInstance().query_parameter_posistion(m_eventIdentifier, parameter_name);
	if (parameter_postion == -1) {
		return EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE;
	}
	else {
		return m_vctParameterList[parameter_postion].d;
	}
	return EVENT_RECORD_DEFAULT_DATA_PARAMETER_VALUE;
}

bool EventRecord::SetParameter(parameter_index_enum parameter_name, wstring parameter_value)
{
	int parameter_postion = EventRecordManager::GetInstance().get_parameter_posistion(m_eventIdentifier, parameter_name);
	if (parameter_postion == m_vctParameterList.size())
	{
		ParameterValue new_parameter;
		new_parameter.s = parameter_value;
		m_vctParameterList.push_back(new_parameter);
	}
	else if (parameter_postion > m_vctParameterList.size())
	{
		//TODO: add log
	}
	else
	{
		m_vctParameterList[parameter_postion].s = parameter_value;
	}

	return true;
}

bool EventRecord::SetParameter(parameter_index_enum parameter_name, ULONG64 parameter_value)
{
	int parameter_postion = EventRecordManager::GetInstance().get_parameter_posistion(m_eventIdentifier, parameter_name);
	if (parameter_postion == m_vctParameterList.size())
	{
		ParameterValue new_parameter;
		new_parameter.d = parameter_value;
		m_vctParameterList.push_back(new_parameter);
	}
	else if (parameter_postion > m_vctParameterList.size())
	{
		//TODO: add log
	}
	else
	{
		m_vctParameterList[parameter_postion].d = parameter_value;
	}

	return true;
}

int EventRecord::get_process_id_()
{
	return m_dwProcessId;
}

int EventRecord::get_thread_id_()
{
	return m_dwThreadId;
}

void EventRecord::set_event_identifier_(EventIdentifier temp_identifier)
{
	m_eventIdentifier = temp_identifier;
}
// add by zxw on 20210507
void EventRecord::update_process_id2network_time_map_(DWORD pid, ULONG64 ulTime)
{
    if (m_umapPid2NetworkTime.count(pid))
    {
        m_umapPid2NetworkTime[pid] = ulTime;
    }
}
// add by zxw on 20210507
ULONG64 EventRecord::get_process_network_timestamp(DWORD pid) 
{
    auto it = m_umapPid2NetworkTime.find(pid);
    if (it != m_umapPid2NetworkTime.end())
    {
        return it->second;
    }
    return 0;
}

void EventRecord::QPCtimeToSystime()
{  
	if (!m_bInit)
		init_timecal();
    if (m_liFrequency.QuadPart != 0) {
        ULONG64 intervaltime = (ULONG64)((m_ulTimeStamp - m_ulStartEtwtime) * 10000000.0 / m_liFrequency.QuadPart); //100-ns 
        m_ulTimeStamp = (m_nStartSystemtime + intervaltime) * 100;
    }
	//cout << time_stamp_ << endl;
}

void EventRecord::init_timecal()
{   //Get first timestamp and interval time, to translate time into calculate nanoseconds since 1970.1.1 0:0:0:000
	if (!QueryPerformanceFrequency(&m_liFrequency))
	{
        WriteLog4cPlus(ERROR_LEVEL, L"init_timecal QueryPerformanceFrequency failed err: %d", GetLastError());
        return;
	}
    
	m_ulStartEtwtime = m_ulTimeStamp;
	FILETIME ft;
	GetSystemTimeAsFileTime(&ft);
	ULONG64 current_tics = (unsigned __int64)ft.dwLowDateTime + (((unsigned __int64)ft.dwHighDateTime) << 32);
	//SystemTimeToFileTime(&sttime, (LPFILETIME)&start_systemtime);
	m_nStartSystemtime = current_tics - EPOCHFILETIME;  // FILETIME start from 1960.1.1,should translate into 1970
	m_bInit = true;
}

EventIdentifier& EventRecord::get_event_identifier_()
{
	return m_eventIdentifier;
}

bool EventRecord::Output()
{
	QPCtimeToSystime();
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(this);
	return true;
}
