#include "stdafx.h"
#include "tool_functions.h"
#include "output_json.h"
#include "json_include/rapidjson/writer.h"
#include "json_include/rapidjson/document.h"
#include "json_include/rapidjson/prettywriter.h"
#include "json_include/rapidjson/stringbuffer.h"
#include "event_record.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "init_collector.h"
#include "time_util.h"
#include "event_record_manager.h"
#include "parameter_index.h"

OutputJson::OutputJson()
{
	String log_filename = TimeUtil::NowString() + ".out";
	outfile = fopen(log_filename.c_str(), "w+");

	WriteLog4cPlus(INFO_LEVEL, L"InitRecordJson");
}

OutputJson::~OutputJson()
{

}

bool OutputJson::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return false;
	// add by zxw on 20191128 裁剪无用的事件
	if (rec->isUseless())
		return true;

	rapidjson::Document record_document;
	rapidjson::Document::AllocatorType& doc_allocator = record_document.GetAllocator();
	rapidjson::Value rec_doc_root(rapidjson::kObjectType);
	rec_doc_root.AddMember("processID", long(rec->m_dwProcessId), doc_allocator);
	rec_doc_root.AddMember("threadID", long(rec->m_dwThreadId), doc_allocator);
	rapidjson::Value uint;
	uint.SetUint64(rec->m_ulTimeStamp);
	rec_doc_root.AddMember("TimeStamp", uint, doc_allocator);
	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(rec->m_eventIdentifier);
	if (ix != EventRecordManager::GetInstance().m_mapEventStrucp.end())
	{
		rec_doc_root.AddMember("EventName", rapidjson::StringRef(ix->first.event_name().c_str()), doc_allocator);
	}

	if (rec->m_eventIdentifier.provider_id() == ETWStackWalk)
	{
		rapidjson::Value str_val;
		String stack_str = ((EventRecordCallstack*)rec)->GetOutputInfo();
		str_val.SetString(stack_str.c_str(), (rapidjson::SizeType)stack_str.size(), doc_allocator);
		rec_doc_root.AddMember("CallStack", str_val, doc_allocator);
	}
	//else
	{
		rapidjson::Value argu_doc(rapidjson::kObjectType);
		for (int i = 0; i < rec->m_vctParameterList.size(); i++)
		{
			const char* parm_name;
			parm_name = json_parameter_name_list[EventRecordManager::GetInstance().m_mapEventStrucp[rec->m_eventIdentifier][i].name];
			String parameter_name(parm_name);
            if (g_parameter_string.find(parameter_name) != g_parameter_string.end())
            {          
				String parm;
				parm = ToolFunctions::WStringToString(rec->m_vctParameterList[i].s);
				rapidjson::Value str_val;
				str_val.SetString(parm.c_str(), (rapidjson::SizeType)parm.length(), doc_allocator);
				argu_doc.AddMember(
					rapidjson::StringRef(parm_name),
					str_val,
					doc_allocator);
			}
			else
			{
				argu_doc.AddMember(rapidjson::StringRef(parm_name), rec->m_vctParameterList[i].d, doc_allocator);
			}
		}
		rec_doc_root.AddMember("arguments", argu_doc, doc_allocator);
	}

	rapidjson::StringBuffer buffer;
	rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
	rec_doc_root.Accept(writer);
	output_event_sum++;
	rec_json = buffer.GetString();
	fprintf(outfile, "%s\n", rec_json.c_str());
	fflush(outfile);
	if (output_event_sum % OUTPUT_JSON_REPEAT_TIMES == 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		std::cout << std::endl;
		std::cout << std::dec << "output: " << output_event_sum << "events. " << std::endl;
		std::cout << std::endl;
#endif // OUTPUT_COMMAND_LINE;
	}

	return true;
}
