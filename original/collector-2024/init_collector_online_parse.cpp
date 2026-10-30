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
#include "named_pipe_client.h"
#include "tool_functions.h"
#include "event_record_pruner.h"
#include "macro_detector.h"
#include "extra_trace_session.h"
#include "system_call_detector.h"
#include "security_trace_session.h"
#include "sysmon_trace_session.h"
#include "RansomCheck.h"

std::vector<std::unordered_map<DWORD, ULONG64>> InitCollectorOnlineParse::m_vct2mapLastDetectTime(2);	// remotedesktop

DWORD InitCollectorOnlineParse::m_dwApplicationFrameHostPid = 0;

EventRecordQueue InitCollectorOnlineParse::_switch_event_queue;

void InitCollectorOnlineParse::InitPipe()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitNamePipe");
	//pipe.CreateNamedPipeInServer();
	NamedPipeClient::GetInstance().InitPipe();
	WriteLog4cPlus(INFO_LEVEL, L"InitNamePipeSuccess");
}

void InitCollectorOnlineParse::Init()
{
	//EventRecord::SetRunningModeFlag(Setting::GetInstance().GetChar("mode"));
	EventRecord::SetRunningModeFlag(Setting::GetInstance().collector_mode());
	RansomCheck::initDetectFlag();
	if (!Setting::GetInstance().enable_ransom_detector() && Setting::GetInstance().local_detector_parse())
	{
		PhfDetector::GetInstance().InitMLAPIFilter();
	}
	InitDefaultValue();
	InitEventStruct();//get eventstruct from format.txt
	InitOutput();
	InitFilter();
	InitThreadTask(); //create thread for image certificate,visible window,ipconfig,etc;
	if (m_nDetectorMode == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK)
	{
		InitCallStackEnableEvent();
		WriteLog4cPlus(INFO_LEVEL, L"InitCallstackDetectorMode");
	}
	else
	{
		SystemCallDetector::GetInstance().Init();
		WriteLog4cPlus(INFO_LEVEL, L"InitSysCallDetectorMode");
	}
#ifndef STANDALONE_COLLECTOR
	InitPipe();
#endif
	//GetSystemContext();
	//InitKeyAndMouseHook(); //To get Keyboard and mouse info,only use  in Wushang's part

	MacroDetector::GetInstance().Init();
    // add by zxw on 20200303 new security audit
    SecurityTraceSession::GetInstance().Init();
}

void InitCollectorOnlineParse::Excute()
{
	ExtraTraceSession::GetInstance().StartSession();
	SecurityTraceSession::GetInstance().StartSession();
    SysmonTraceSession::GetInstance().StartSession();
	int status = m_etwConfiguration.ConfigureEtwSession(true, ConsumeEvent);
	if (status == -1)
    {
#ifdef OUTPUT_COMMAND_LINE      
		std::cout << "You may have problem in start collector, Please connect with Administrator" << std::endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(ERROR_LEVEL, L"You may have problem in start collector, Please connect with Administrator");
	}

	WriteLog4cPlus(ERROR_LEVEL, L"InitCollectorOnlineParse::Excute: ETW session exit");
}

void InitCollectorOnlineParse::Clean()
{
    ExtraTraceSession::GetInstance().StopSession();
    SecurityTraceSession::GetInstance().StopSession();
    SysmonTraceSession::GetInstance().StopSession();
    Sleep(100);
	ThreadTaskManager::GetInstance().Clean();
}

void InitCollectorOnlineParse::CacheClean()
{
	if (m_bCacheCleanFlag)
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

		m_bCacheCleanFlag = false;
	}
}

void InitCollectorOnlineParse::PushSwitchEventRecord(EventRecord* switch_rec)
{
	_switch_event_queue.enqueue(switch_rec);
}

void InitCollectorOnlineParse::InitFilter()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitFilter");
	Filter::GetInstance().Init();
}

VOID WINAPI InitCollectorOnlineParse::ConsumeEvent(PEVENT_RECORD p_event)
{
	/*if (p_event->EventHeader.ProcessId == ULONG_MAX) {	
		return;
	}*/

//#ifdef ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST	
//	RecordEvent(p_event);
//	//return;
//#endif

	EventRecord* switch_rec;
	while (_switch_event_queue.try_dequeue(switch_rec))
	{
		_ProcessEventRecord(switch_rec);
	}

	CacheClean();

	if (!Filter::GetInstance().FilterBeforeRecInstance(p_event->EventHeader.ProviderId.Data1
		, p_event->EventHeader.EventDescriptor.Opcode
		, p_event->EventHeader.ProcessId)) 
		return;
    
	EventRecord* rec = EventRecordManager::GetInstance().ParseEventRecord(p_event);
	if (!rec)
	{
        WriteLog4cPlus(ERROR_LEVEL, L"EventRecord new failed errcode: %d", GetLastError());
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
	//if (Setting::GetInstance().GetBool("enable_performance_monitor"))
	if (Setting::GetInstance().enable_performace_monitor())
	{
		ThreadTaskManager::GetInstance().AddTask(MONITOR_TASK_MODE);
	}

	//ThreadTaskManager::GetInstance().AddTask(GET_VISIBLE_WINDOW_TASK_MODE);
	ThreadTaskManager::GetInstance().AddTask(CERTIFICATE_IMAGE_TASK_MODE);
	//ThreadTaskManager::GetInstance().AddTask(GET_IPCONFIG_TASK_MODE);
	ThreadTaskManager::GetInstance().AddTask(TIMER_TASK_MODE);

    // add by zxw on 2200915
    ThreadTaskManager::GetInstance().AddTask(GET_DEVICE_ARRIVAL_TASK_MODE);
    // add by zxw on 20201012
    /*if (Setting::GetInstance().enable_rule_match())
    {
        ThreadTaskManager::GetInstance().AddTask(RULE_MATCHER_TASK_MODE);
    }*/
    // add by zxw on 2201027
    ThreadTaskManager::GetInstance().AddTask(GEE_HASH_TASK_MODE);
    // add autorun event
	//ThreadTaskManager::GetInstance().AddTask(PARSE_AUTORUN_TASK_MODE);
#ifndef STANDALONE_COLLECTOR
	ThreadTaskManager::GetInstance().AddTask(PIPE_READ_TASK_MODE);
#endif
	//ThreadTaskManager::GetInstance().AddTask(PARSE_EVENT_TASK_MODE);

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
	if (!rec->Output())
	{
		EventRecordManager::GetInstance().RecycleEventRecord(rec);
	}
}
#ifdef ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST	
VOID InitCollectorOnlineParse::RecordEvent(PEVENT_RECORD p_event)
{
	bool bAdd = false;
	std::string strT;
	strT = std::to_string(p_event->EventHeader.Flags);
	strT += ",";
	strT += std::to_string(p_event->EventHeader.ProviderId.Data1);
	strT += ",";
	switch (p_event->EventHeader.ProviderId.Data1)
	{
	case ETWFileIo:
		strT += "ETWFileIo";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case FileioNameEvent:
			strT += "FileioNameEvent";
			break;
		case FileioFileCreateEvent:
			strT += "FileioFileCreateEvent";
			break;
		case FileioCreateEvent:
			strT += "FileioCreateEvent";
			break;
		case FileIoCleanup:
			strT += "FileIoCleanup";
			break;
		case FileioClose:
			strT += "FileioClose";
			break;
		case FileIoRead:
			strT += "FileIoRead";
			break;
		case FileIoWirte:
			strT += "FileIoWirte";
			break;
		case FileIoDelete:
			strT += "FileIoDelete";
			break;
		case FileioRenameEvent:
			strT += "FileioRenameEvent";
			break;
		case FileioDirEnumerationEvent:
			strT += "FileioDirEnumerationEvent";
			break;
		case FileIoRenamePath:
			strT += "FileIoRenamePath";
			break;
		default:
			strT += "default";
			break;
		}
		//bAdd = true;
		break;
	case ETWThread:
		strT += "ETWThread";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case ThreadStart:
			strT += "ThreadStart";
			break;
		case ThreadEnd:
			strT += "ThreadEnd";
			break;
		case ThreadDCStart:
			strT += "ThreadDCStart";
			break;
		case ThreadContextSwitch:
			strT += "ThreadContextSwitch";
			break;
		default:
			strT += "default";
			break;
		}
		//bAdd = true;
		break;
	case ETWProcess:
		strT += "ETWProcess";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case ProcessStart:
			strT += "ProcessStart";
			break;
		case ProcessEnd:
			strT += "ProcessEnd";
			break;
		case ProcessDCStart:
			strT += "ProcessDCStart";
			break;
		case ProcessDCEnd:
			strT += "ProcessDCEnd";
			break;
		default:
			strT += "default";
			break;
		}
		bAdd = true;
		break;
	case ETWImage:
		strT += "ETWImage";
		strT += ",";
		strT += "default";
		bAdd = true;
		break;
	case ETWRegistry:
		strT += "ETWRegistry";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case RegistryCreate:
			strT += "RegistryCreate";
			break;
		case RegistryOpen:
			strT += "RegistryOpen";
			break;
		case RegistryQuery:
			strT += "RegistryQuery";
			break;
		case RegistryRegistrySetValuee:
			strT += "RegistryRegistrySetValuee";
			break;
		case RegistryQueryValue:
			strT += "RegistryQueryValue";
			break;
		case RegistrySetInformation:
			strT += "RegistrySetInformation";
			break;
		case RegistryKCBCreate:
			strT += "RegistryKCBCreate";
			break;
		case RegistryKCBDelete:
			strT += "RegistryKCBDelete";
			break;
		case RegistryDelete:
			strT += "RegistryDelete";
			break;
		case RegistryDeleteValue:
			strT += "RegistryDeleteValue";
			break;
		case RegistryClose:
			strT += "RegistryClose";
			break;
		default:
			strT += "default";
			break;
		}
		break;
	case ETWALPC:
		strT += "ETWALPC";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case AlpcSendEvent:
			strT += "AlpcSendEvent";
			break;
		case ApcReceiveEvent:
			strT += "ApcReceiveEvent";
			break;
		default:
			strT += "default";
			break;
		}
		break;
	case ETWDiskIo:
		strT += "ETWDiskIo";
		strT += ",";
		strT += "default";
		break;
	case ETWPerfInfo:
		strT += "ETWPerfInfo";
		strT += ",";
		strT += "default";
		break;
	case ETWTcpIp:
		strT += "ETWTcpIp";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case TcpIpSendIPV4:
			strT += "TcpIpSendIPV4";
			break;
		case TcpIpRecvIPV4:
			strT += "TcpIpRecvIPV4";
			break;
		default:
			strT += "default";
			break;
		}
		break;
	case ETWUdpIp:
		strT += "ETWUdpIp";
		strT += ",";
		switch (p_event->EventHeader.EventDescriptor.Opcode)
		{
		case UdpIpSendIPV4:
			strT += "UdpIpSendIPV4";
			break;
		case UdpIpRecvIPV4:
			strT += "UdpIpRecvIPV4";
			break;
		default:
			strT += "default";
			break;
		}
		break;
	case ETWStackWalk:
		strT += "ETWStackWalk";
		strT += ",";
		strT += "default";
		break;
	default:
		strT += "default";
		strT += ",";
		strT += "default";
	};
	strT += ",";
	strT += std::to_string(p_event->EventHeader.EventDescriptor.Opcode);
	strT += ",";
	strT += std::to_string(p_event->EventHeader.EventDescriptor.Id);
	strT += ",";
	strT += std::to_string(p_event->EventHeader.ThreadId);
	strT += ",";
	strT += std::to_string(p_event->EventHeader.ProcessId);
	strT += ",";
	strT += std::to_string(p_event->EventHeader.TimeStamp.QuadPart);
	strT += ",";
	wchar_t szGuid[50] = { 0 };
	StringFromGUID2(p_event->EventHeader.ProviderId, szGuid, sizeof(szGuid));
	std::string strTT = CPykMgrTemplate<CP_ACP>(szGuid);
	strT += strTT;
	if (bAdd)
		g_thCRC.AddLine("ParseEventRecord", strT.c_str());
}
#endif