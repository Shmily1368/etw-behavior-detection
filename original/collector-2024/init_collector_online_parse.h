/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(版本号);
	Description:	初始化采集器的在线解析子类;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019.01.07    |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "init_collector.h"
#include "record_queue_per_process.h"

class InitCollectorOnlineParse : public InitCollector
{
public:
	InitCollectorOnlineParse() : InitCollector(EM_InitCollectorMode::ONLINE_PARSE_MODE) { }

	void InitPipe();

	virtual void Init() override;
	virtual void Excute() override;
	virtual void Clean() override;
	virtual void InitFilter();

	static VOID WINAPI ConsumeEvent(PEVENT_RECORD p_event);
	static void CacheClean();
	static void PushSwitchEventRecord(EventRecord* switch_rec);

	static std::vector<std::unordered_map<DWORD, ULONG64>> m_vct2mapLastDetectTime; // 0--remotedesktop,1--audiorecord
	static DWORD m_dwApplicationFrameHostPid;

#ifdef ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST	
	static VOID RecordEvent(PEVENT_RECORD p_event);
#endif
protected:
	void InitThreadTask() override;
	static void _ProcessEventRecord(EventRecord* rec);

private:
	//not used
	//STRING_SET _autorun_apps;

	/*moodycamel::ConcurrentQueue<EventRecord*>;*/
	static EventRecordQueue _switch_event_queue;
};
