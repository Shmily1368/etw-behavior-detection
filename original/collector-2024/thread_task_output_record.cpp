#include "stdafx.h"
#include "thread_task_output_record.h"
#include "init_collector.h"
#include "global_enum_def.h"
#include "event_record_subclass.h"
#include "tool_functions.h"
#include "init_collector_online_parse.h"

void OutputRecordThreadTask::_Excute()
{
	while (!_stop_flag)
	{
		if (InitCollector::GetCollector())
		{
			EventRecord* rec = InitCollector::GetCollector()->PopSendRecord();
			if (rec)
			{
				InitCollector::GetCollector()->OutputEventRecord(rec);
                m_outputcounts++;
			}
			else
			{
				Sleep(10);
			}
		}
		else
		{
			Sleep(10);
		}
		
	}
}

OutputRecordThreadTask::OutputRecordThreadTask()
	: BaseThreadTask(OUTPUT_RECORD_TASK_MODE)
{
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(new EventInitSignal());
}

OutputRecordThreadTask::~OutputRecordThreadTask()
{

}

void OutputRecordThreadTask::Log()
{
	if (InitCollector::GetCollector())
	{
		size_t num = InitCollector::GetCollector()->WaitSendDataSize();
		WriteLog4cPlus(INFO_LEVEL, L"NumLog: wait_send_dataqueue: %d", num);
	}
    // ADD BY ZXW ON 20200525
    if (clock() - m_stime >= MS_ONE_SECOND*60)
    {
        if (m_outputlast == m_outputcounts)
        {
            WriteLog4cPlus(WARN_LEVEL, L"collector has no event for one minute,restart!");
            quick_exit(0);
        }
        m_stime = clock();
        m_outputlast = m_outputcounts;
    }
}

void OutputRecordThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitOutputRecordThread");
}
