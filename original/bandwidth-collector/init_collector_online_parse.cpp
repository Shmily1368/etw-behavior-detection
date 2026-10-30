#include "stdafx.h"
#include <functional>
#include <fstream>
#include <io.h>

#include "init_collector_online_parse.h"
#include "event_record_subclass.h"
#include "global_enum_def.h"
#include "setting.h"
#include "obtain_entry_address.h"
#include "ntkernel_provider_guid.h"
#include "thread_task_manager.h"
#include "filter.h"
#include "tool_functions.h"
#include "event_record_pruner.h"

std::vector<std::unordered_map<DWORD, ULONG64>> InitCollectorOnlineParse::last_detect_time(2);	// remotedesktop

DWORD InitCollectorOnlineParse::application_frame_host_pid = 0;

EventRecordQueue InitCollectorOnlineParse::_switch_event_queue;


void InitCollectorOnlineParse::Init()
{
	//EventRecord::SetRunningModeFlag(Setting::GetInstance().GetChar("mode"));
	EventRecord::SetRunningModeFlag(Setting::GetInstance().collector_mode());
	PhfDetector::GetInstance().InitMLAPIFilter();
	InitDefaultValue();
	InitEventStruct();//get eventstruct from format.txt
	InitOutput();
	InitFilter();
	InitThreadTask(); //create thread for image certificate,visible window,ipconfig,etc;
	InitCallStackEnableEvent();
}

void InitCollectorOnlineParse::Excute()
{
	int status = _etw_configuration.ConfigureEtwSession(true, ConsumeEvent);
	if (status == -1)
    {
#ifdef OUTPUT_COMMAND_LINE      
		std::cout << "You may have problem in start collector, Please connect with Administrator" << std::endl;
#endif // OUTPUT_COMMAND_LINE;
		LoggerRecord::WriteLog(L"You may have problem in start collector, Please connect with Administrator", ERR);
	}

	LoggerRecord::WriteLog(L"InitCollectorOnlineParse::Excute: ETW session exit", LogLevel::ERR);
}

void InitCollectorOnlineParse::Clean()
{
    Sleep(100);
	ThreadTaskManager::GetInstance().Clean();
}

void InitCollectorOnlineParse::CacheClean()
{
	if (one_hour_cache_clean_flag)
	{
		ToolFunctions::CleanCache();

        // add by zxw on 20200424 clean fileio cache
        EventRecordPruner::GetInstance().CleanCache();

		//EventRecordCallstack cache clean
		{
			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_1;
			vector_empty_1.swap(EventRecordCallstack::process_address_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_2;
			vector_empty_2.swap(EventRecordCallstack::process_address_useless_cache);

			std::unordered_map<DWORD, std::unordered_set<ULONG64>> vector_empty_3;
			vector_empty_3.swap(EventRecordCallstack::APIaddress_keepon_cache);

			std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>> vector_empty_4;
			vector_empty_4.swap(EventRecordCallstack::process_API_address_cache);
		}

		one_hour_cache_clean_flag = false;
	}
}

void InitCollectorOnlineParse::PushSwitchEventRecord(EventRecord* switch_rec)
{
	_switch_event_queue.enqueue(switch_rec);
}

void InitCollectorOnlineParse::InitFilter()
{
	LoggerRecord::WriteLog(L"InitFilter", INFO);
	Filter::GetInstance().Init();
}

VOID WINAPI InitCollectorOnlineParse::ConsumeEvent(PEVENT_RECORD p_event)
{
	EventRecord* switch_rec;
	while (_switch_event_queue.try_dequeue(switch_rec))
	{
		_ProcessEventRecord(switch_rec);
	}

	CacheClean();

	if (!Filter::GetInstance().FilterBeforeRecInstance(p_event->EventHeader.ProviderId.Data1, p_event->EventHeader.EventDescriptor.Opcode, p_event->EventHeader.ProcessId)) return;
    
	EventRecord* rec = EventRecordManager::GetInstance().ParseEventRecord(p_event);
	if (!rec)
	{
        LoggerRecord::WriteLog(L"EventRecord new failed errcode:" + std::to_wstring(GetLastError()), ERR);
		return;
	}
 
	rec->InitParse();

	// add by zxw on 20191030
	// 特权进程,获取本机ip但是不上报事件
	if (Filter::GetInstance().IsPrivilegeProcess(rec->get_process_id_()))
	{
		if (rec->get_event_identifier_().provider_id() == ETWTcpIp)
		{
			// 设置本机IP
			Filter::GetInstance().SetLoclaIPbyEventRecord((EventRecordTcpip*)rec);
		}
		
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}
	//


	if (!Filter::GetInstance().FilterAfterRecInstance(rec))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}

	_ProcessEventRecord(rec);
}

void InitCollectorOnlineParse::InitThreadTask()
{
	ThreadTaskManager::GetInstance().AddTask(TIMER_TASK_MODE);
	ThreadTaskManager::GetInstance().MonitorTask();
}

void InitCollectorOnlineParse::_ProcessEventRecord(EventRecord* rec)
{
	rec->parse();
	
	GetCollector()->SetProcessLastEvent(rec->get_process_id_(), rec->get_event_identifier_().provider_id(), rec->get_event_identifier_().opcode());

	//get process_id to filter
	//mainly filter PID in black list, because fileiofilecreate and fileiocreate is need to match rename event and macro ,we do not filter it here
	if (!Filter::FilterAfterParseRecord(rec))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
		return;
	}
	
	rec->SetProcessTcpPreEventRecord(rec);
	
	if (rec->get_event_identifier_().provider_id() != ETWStackWalk) {
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
	}
	else
	{
		if (!rec->Output())
		{
			EventRecordManager::GetInstance().RecycleEventRecord(rec);
		}
	}
	
}
