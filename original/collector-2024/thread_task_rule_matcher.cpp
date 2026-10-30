#include "stdafx.h"
#include "thread_task_rule_matcher.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "concurrent_queue.h"
#include "rule_matcher.h"

RuleMatcherThreadTask::RuleMatcherThreadTask()
	: BaseThreadTask(RULE_MATCHER_TASK_MODE)
{
	
}

RuleMatcherThreadTask::~RuleMatcherThreadTask()
{

}

void RuleMatcherThreadTask::_Excute()
{
	while (!_stop_flag) 
	{
		if (!m_queueCertificateData.empty())
		{
			EventRecord* event_record = nullptr;
			bool flag = m_queueCertificateData.front_pop(event_record);
			if (!flag) continue;
            SRule srule;
            if (rule_matcher::GetInstance().event_rule_matcher(event_record, srule))
            {
                WriteLog4cPlus(INFO_LEVEL, L"RuleMatcherThreadTask send rule %d", srule.rule_id);
                // 上报事件
                EventRecord* rec = EventRecordManager::GetInstance().ParseRuleIdentifierEvent(event_record, srule);
                if (rec && InitCollector::GetCollector())
                    InitCollector::GetCollector()->PushSendRecord(rec);
            }

            SAFE_DELETE(event_record);
		}
		else 
		{
			m_signal.Wait();
		}
	}
}

void RuleMatcherThreadTask::Log()
{
	int size = m_queueCertificateData.size();

	WriteLog4cPlus(INFO_LEVEL, L"RuleMatcherThreadTask::Log:certificate_data_queue size is %d", size);
}

void RuleMatcherThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitRuleMatcher");
    //rule_matcher::GetInstance().add_rule_map_by_file("rulematcher");    
}

void RuleMatcherThreadTask::Stop()
{
	_stop_flag = true;
	m_signal.NotifyOne();
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void RuleMatcherThreadTask::AddData(EventRecord* record)
{
	m_queueCertificateData.push(record);
	m_signal.NotifyOne();
}
