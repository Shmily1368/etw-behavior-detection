/********************************************************************
	Created:		2018-04-09
	Author:			chips;
	Version:		1.1.0(版本号);
	Description:	用于etw数据配置;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/04/09 |	1.0.0	 |	Zhenyuan	  | Create file
----------------------------------------------------------------------------
  2019/01/04 |	1.1.0	 |	chips		  | 删除额外的对成员变量进行配置的函数，在类构造时引入配置;
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#include <Windows.h>
#include <evntrace.h>
#include "tool_functions.h"
class ETWConfiguration
{
public:
	// store the events whose call stack was enable
	static std::set<int> m_setEnableStackEvents;

	ETWConfiguration();
	~ETWConfiguration();
    void SetTraceProperties(EVENT_TRACE_PROPERTIES* pSessionProperties, ULONG BufferSize, bool is_real_time);
	int ConfigureEtwSession(bool is_real_time, void __stdcall consum_event_realtime(PEVENT_RECORD));
	ULONG StopEtwSession();
	void ConsumeLogFile(void __stdcall consum_event_realtime(PEVENT_RECORD));

	inline void SetLogfilePath(std::wstring logfile_path) {
		m_strLogfilePath = logfile_path;
	}
	void SetEnableStackEvents(std::vector<CLASSIC_EVENT_ID> enable_stack_events);
private:

	bool m_bLowMode;
	ULONG m_ulEnableFlag = 0;
	std::wstring m_strLogfilePath; 
	std::wstring m_wcsSessionName;
	std::vector<CLASSIC_EVENT_ID> m_vctEnableStackEvents;
	TRACEHANDLE m_thSessionHandle = 0;
	EVENT_TRACE_PROPERTIES* m_pSessionProperties = NULL;

	void _EventMonitorExec();
	inline void Preemption() 
	{
		const static std::string m_strSessionName = ToolFunctions::WStringToString(m_wcsSessionName);
		const static std::string m_strCommandLine = "logman stop \"" + m_strSessionName + "\" -ets > nul";
		system(m_strCommandLine.c_str());
	}
	void SetupEventConsumer(void __stdcall consum_event_realtime(PEVENT_RECORD));
	inline void SetupEventStackwalk();
};

