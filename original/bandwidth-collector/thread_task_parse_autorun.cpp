#include "stdafx.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "event_record_subclass.h"
#include "thread_task_parse_autorun.h"
#include "init_collector_online_parse.h"
#include "setting.h"

void ParseAutorunThreadTask::_Excute()
{
	LoggerRecord::WriteLog(L"ParseAutorunThreadTask::_Excute", LogLevel::INFO);
	STRING_SET autorun_info;
	ToolFunctions::ParseAutorunInfo(autorun_info);

	STRING_VECTOR autorun_info_vec;
	std::copy(autorun_info.begin(), autorun_info.end(), std::back_inserter(autorun_info_vec));
	String autorun_info_join = StringUtil::Join(autorun_info_vec, 0, "|");
	auto tempautorun = ToolFunctions::StringToWString(autorun_info_join);
	LoggerRecord::WriteLog(L"ParseAutorun: filename:"+ tempautorun, LogLevel::INFO);
	EventAutorunInfo* ev = new EventAutorunInfo(autorun_info_join);
	// add by zxw on 20191107 添加空指针保护
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(ev);
	else
	{
		EventRecordManager::GetInstance().RecycleEventRecord(ev);
		LoggerRecord::WriteLog(L"ParseAutorun::InitCollector::GetCollector is null ", LogLevel::ERR);
	}
}


ParseAutorunThreadTask::ParseAutorunThreadTask()
	: BaseThreadTask(PARSE_AUTORUN_TASK_MODE)
{
	
}

ParseAutorunThreadTask::~ParseAutorunThreadTask()
{
	
}

void ParseAutorunThreadTask::Log()
{
		
}

void ParseAutorunThreadTask::Init()
{
	LoggerRecord::WriteLog(L"InitParseAutorunThread", INFO);
}
