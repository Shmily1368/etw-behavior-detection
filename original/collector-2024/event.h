#pragma once

#include <iostream>
#include <string>
#include "tool_functions.h"
#include "event_record_manager.h"
#include "ThirdPart/cJSON/include/cJsonHelper.hpp"
using namespace std;

class argument {
public:
	string IrpPtr = "";
	string FileObject = "";
	int64 Offset = -1;
	int64 IoSize = -1;
	int64 IoFlags = -1;
	int64 CreateOptions = -1;
	int64 FileAttributes = -1;
	int64 ShareAccess = -1;
	string OpenPath = "";
	int64 ProcessId = -1;
	string ImageFileName = "";
	int32 size = -1;
	string magic = "";
	string sdhash = "";
	int32 action = -1;
	string toString(void) {                          //print the format which svm needs.
		stringstream ss;
		string output;
		ss << "{";
		ss << " IrpPtr:" << IrpPtr;
		ss << " FileObject:" << FileObject;
		ss << " Offset:" << Offset;
		ss << " IoSize:" << IoSize;
		ss << " IoFlags:" << IoFlags;
		ss << " CreateOptions:" << CreateOptions;
		ss << " FileAttributes:" << FileAttributes;
		ss << " ShareAccess:" << ShareAccess;
		ss << " OpenPath:" << OpenPath;
		ss << " ProcessId:" << ProcessId;
		ss << " ImageFileName:" << ImageFileName;
		ss << " size:" << size;
		ss << " magic:" << magic;
		ss << " action:" << action;
		ss << "}";
		output = ss.str();
		return output;
	}
#ifdef ETW_EVENT_RECORD_TEST	
	VOID Record2csv(stringstream& ss)
	{
		ss << IrpPtr << ",";
		ss << FileObject << ",";
		ss << Offset << ",";
		ss << IoSize << ",";
		ss << IoFlags << ",";
		ss << CreateOptions << ",";
		ss << FileAttributes << ",";
		ss << ShareAccess << ",";
		ss << OpenPath << ",";
		ss << ProcessId << ",";
		ss << ImageFileName << ",";
		ss << size << ",";
		ss << magic << ",";
		ss << action << ",";
	}
#endif
};
class event{
public:
	event(){
		;
	}
	event(string eventname, int32 pid, int64 timestamp) {
		EventName = eventname;
		processID = pid;
		TimeStamp = timestamp;
	}
	event(string eventline) {                                           //use cJsonObject to parsr json and create event 
		
		auto pJsonData = cJSON_Parse(eventline.c_str());
		if (NULL != pJsonData)
		{
			cJsonHelper::GetItemInt(pJsonData, "processID", processID);
			string time;
			cJsonHelper::GetJsonString(pJsonData, "TimeStamp", time);
			if (time != "") {
				TimeStamp = gettime(time);
			}
			cJsonHelper::GetJsonString(pJsonData, "EventName", EventName);
			if (EventName.length() != 0)
			{
				if (EventName == "ProcessStart" || EventName == "ProcessDCStart") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					cJsonHelper::GetJsonString(pArguments, "ImageFileName", this->arguments.ImageFileName);
					int nProcessId = 0;
					cJsonHelper::GetItemInt(pArguments, "ProcessId", nProcessId);
					this->arguments.ProcessId = nProcessId;
				}
				else if (EventName == "ProcessEnd" || EventName == "ProcessDCEnd") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					int nProcessId = 0;
					cJsonHelper::GetItemInt(pArguments, "ProcessId", nProcessId);
					this->arguments.ProcessId = nProcessId;
				}
				else if (EventName == "FileIoCreate") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					cJsonHelper::GetJsonString(pArguments, "IrpPtr", this->arguments.IrpPtr);
					cJsonHelper::GetJsonString(pArguments, "FileObject", this->arguments.FileObject);
					cJsonHelper::GetJsonString(pArguments, "OpenPath", this->arguments.OpenPath);
					int nCreateOptions = 0;
					int nFileAttributes = 0;
					int nShareAccess = 0;
					cJsonHelper::GetItemInt(pArguments, "CreateOptions", nCreateOptions);
					cJsonHelper::GetItemInt(pArguments, "FileAttributes", nFileAttributes);
					cJsonHelper::GetItemInt(pArguments, "ShareAccess", nShareAccess);
					this->arguments.CreateOptions = nCreateOptions;
					this->arguments.FileAttributes = nFileAttributes;
					this->arguments.ShareAccess = nShareAccess;
				}
				else if (EventName == "FileIoCleanup" || EventName == "FileIoDirEnum" || EventName == "FileIoDelete" || EventName == "FileIoRename") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					cJsonHelper::GetJsonString(pArguments, "IrpPtr", this->arguments.IrpPtr);
					cJsonHelper::GetJsonString(pArguments, "FileObject", this->arguments.FileObject);
				}
				else if (EventName == "FileIoRead" || EventName == "FileIoWrite") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					cJsonHelper::GetJsonString(pArguments, "IrpPtr", this->arguments.IrpPtr);
					cJsonHelper::GetJsonString(pArguments, "FileObject", this->arguments.FileObject);
					int nOffset = 0;
					int nIoSize = 0;
					int nIoFlags = 0;
					cJsonHelper::GetItemInt(pArguments, "Offset", nOffset);
					cJsonHelper::GetItemInt(pArguments, "IoSize", nIoSize);
					cJsonHelper::GetItemInt(pArguments, "IoFlags", nIoFlags);
					this->arguments.Offset = nOffset;
					this->arguments.IoSize = nIoSize;
					this->arguments.IoFlags = nIoFlags;
				}
				else if (EventName == "FileIoChange") {
					auto pArguments = cJSON_GetObjectItem(pJsonData, "arguments");
					cJsonHelper::GetItemInt(pArguments, "size", this->arguments.size);
					cJsonHelper::GetJsonString(pArguments, "sdhash", this->arguments.sdhash);
					cJsonHelper::GetJsonString(pArguments, "FileObject", this->arguments.FileObject);
					cJsonHelper::GetJsonString(pArguments, "magic", this->arguments.magic);
					cJsonHelper::GetItemInt(pArguments, "action", this->arguments.action);
					cJsonHelper::GetJsonString(pArguments, "OpenPath", this->arguments.OpenPath);
					if (this->arguments.OpenPath.length() == 0)
					{
						this->arguments.OpenPath = this->arguments.FileObject;
					}
				}
			}
			else
			{
				cJsonHelper::GetJsonString(pJsonData, "CallStack", CallStack);
			}
		}
		
	};
	
	// add by zxw on 20191114
	event(EventRecord &ev) {   
		processID = ev.get_process_id_();
		TimeStamp = ev.get_time_stamp_();
		auto ix = EventRecordManager::GetInstance().m_mapEventStrucp.find(ev.get_event_identifier_());
		if (ix != EventRecordManager::GetInstance().m_mapEventStrucp.end())
		{
			EventName = ix->first.event_name();
		}

		if (ev.get_event_identifier_().provider_id() == ETWStackWalk)
		{
			CallStack = ev.get_callstack_();			
#ifdef ETW_EVENT_RECORD_TEST
			Record2csv();
#endif
		}
		else
		{
			if (EventName == "ProcessStart" || EventName == "ProcessDCStart") {
				arguments.ImageFileName = ToolFunctions::WStringToString(ev.GetStringParameter(parameter_index_enum::ImageFileName));
				arguments.ProcessId = ev.GetDataParameter(parameter_index_enum::ProcessId);
			}
			else if (EventName == "ProcessEnd" || EventName == "ProcessDCEnd") {
				arguments.ProcessId = ev.GetDataParameter(parameter_index_enum::ProcessId);
			}
			else if (EventName == "FileIoCreate") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
				arguments.CreateOptions = ev.GetDataParameter(parameter_index_enum::CreateOptions);
				arguments.FileAttributes = ev.GetDataParameter(parameter_index_enum::FileAttributes);
				arguments.ShareAccess = ev.GetDataParameter(parameter_index_enum::ShareAccess);
				arguments.OpenPath = ToolFunctions::WStringToString(ev.GetStringParameter(parameter_index_enum::OpenPath));
			}
			else if (EventName == "FileIoCleanup" || EventName == "FileIoDirEnum" || EventName == "FileIoDelete") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
			}
			else if (EventName == "FileIoRename") {
				// we used newfilename as extral info for detection
				arguments.IrpPtr = ToolFunctions::WStringToString(ev.GetStringParameter(parameter_index_enum::NewFileName));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
			}
			else if (EventName == "FileIoRead" || EventName == "FileIoWrite") {
				arguments.IrpPtr = std::to_string(ev.GetDataParameter(parameter_index_enum::IrpPtr));
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
				arguments.Offset = ev.GetDataParameter(parameter_index_enum::Offset);
				arguments.IoSize = ev.GetDataParameter(parameter_index_enum::IoSize);
				arguments.IoFlags = ev.GetDataParameter(parameter_index_enum::IoFlags);
			}
			else if (EventName == "FileIoChange") {		// 暂无此事件，不做详细处理
				arguments.size = (int32)ev.GetDataParameter(parameter_index_enum::size);
				arguments.FileObject = std::to_string(ev.GetDataParameter(parameter_index_enum::FileObject));
			}
		}		
//#ifdef ETW_EVENT_RECORD_TEST
//		Record2csv();
//#endif
	};
	
	int64 gettime(string time) {            //transfer the timestamp from string to int64
		int64 timestamp = stoll(time.substr(0, time.length()-3), nullptr, 0);
		return timestamp;
	}
	// add by zxw on 20191203
	void set_time_stamp(time_t time_stamp) { _time_stamp = time_stamp; }
	time_t get_time_stamp() { return _time_stamp; }
	string toString(void) {                          //print the format which svm needs.
		stringstream ss;
		string output;
		ss << "{";
		ss << " EventName:" << EventName;
		ss << " processID:" << processID;
		ss << " TimeStamp:" << TimeStamp;
		ss << " CallStack:" << CallStack;
		ss << " arguments:" << arguments.toString();
		ss << "}";
		output = ss.str();
		return output;
	}
public:
	string EventName = "";
	int32 processID = -1;
	int64 TimeStamp = -1;
	string CallStack = "";
	argument arguments;

#ifdef ETW_EVENT_RECORD_TEST	
	VOID Record2csv()
	{
		bool bAdd = true;
		stringstream ss;
		string output;
		Record2csv(ss);
		arguments.Record2csv(ss);
		output = ss.str();
		if (bAdd)
			g_thCRC.AddLine("event", output.c_str());
	}

	VOID Record2csv(stringstream& ss)
	{
		ss << EventName << ",";
		ss<< processID << ",";
		ss << TimeStamp << ",";
		ss << CallStack << ",";
	}
#endif
private:
	// add by zxw on 20191203
	time_t _time_stamp;
};
typedef event* pevent;
