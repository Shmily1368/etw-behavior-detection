#include "stdafx.h"
#include "thread_task_pipe_read.h"
#include "named_pipe_client.h"
#include "init_collector.h"
#include "json_include/rapidjson/writer.h"
#include "json_include/rapidjson/stringbuffer.h"
#include "event_record_subclass.h"
#include "tool_functions.h"
#include "filter.h"
#include "task_queue_service.h"
#include "public_json_interface.h"
#include "rule_matcher.h"

PipeReadThreadTask::PipeReadThreadTask()
	: BaseThreadTask(PIPE_READ_TASK_MODE)
{

}

PipeReadThreadTask::~PipeReadThreadTask()
{

}

void PipeReadThreadTask::Log()
{

}

void PipeReadThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitPipeReadThreadTask" );
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_HEALTH_CHECK), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessHealthCheck, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_INIT_TRUST_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessInitTrustList, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_ADD_TRUST_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessAddTrustList, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_REMOVE_TRUST_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessRemoveTrustList, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_CHANGE_TRUST_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessChangeTrustList, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_CHANGE_GEAR), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessChangeGear, this, std::placeholders::_1, std::placeholders::_2), true)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_PARSE_AUTORUN_INFO), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessParseAutorun, this, std::placeholders::_1, std::placeholders::_2), false))); //将autorun事件通过非pipe
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_UPDATE_CLIENT_IP), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessUpdateClientIP, this, std::placeholders::_1, std::placeholders::_2), false)));
	_process_callback_map.insert(std::make_pair(String(PIPE_PROC_RANSOM_SUFFIX_WHITE_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessRansomSuffixWhiteList, this, std::placeholders::_1, std::placeholders::_2), false)));
    _process_callback_map.insert(std::make_pair(String(PIPE_PROC_UPDATE_CUSTOM_RULE), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessUpdateCustomRule, this, std::placeholders::_1, std::placeholders::_2), false)));
    _process_callback_map.insert(std::make_pair(String(PIPE_PROC_RULE_MATCH_SWITCH), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessRuleMatchSwitch, this, std::placeholders::_1, std::placeholders::_2), false)));
    _process_callback_map.insert(std::make_pair(String(PIPE_PROC_CERTIFICATE_WHITE_LIST), PipeProcessCallbackConfig(std::bind(&PipeReadThreadTask::_ProcessCertificateList, this, std::placeholders::_1, std::placeholders::_2), false)));

}

void PipeReadThreadTask::_Excute()
{
	while (!_stop_flag)
	{
		char* read_buf = nullptr;
		if (NamedPipeClient::GetInstance().ReadPipe(&read_buf))
		{
			std::string read_data(read_buf);
			WriteLog4cPlusA(INFO_LEVEL, "PipeReadThreadTask::_Excute: recv data %s", read_data.c_str());

			rapidjson::Document json;
			json.Parse(read_buf);
			if (json.HasParseError())
			{
				String read_data(read_buf);
			}
			else
			{
				_Process(json);
			}

			delete[] read_buf;
		}
		else
		{
			Sleep(MS_ONE_SECOND);
		}
	}
}

void PipeReadThreadTask::_Process(const rapidjson::Document& in_data) const
{
	if (!in_data.HasMember("CMD"))
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ThreadTaskPipeRead::_Process: json parse error");
		return;
	}

	const String& cmd = in_data["CMD"].GetString();
    WriteLog4cPlusA(ERROR_LEVEL, "PipeReadThreadTask::_Process: cmd ", cmd.c_str());

	rapidjson::Document reply;
	reply.SetObject();
	rapidjson::Value value_t;
	value_t.SetString(cmd.c_str(), reply.GetAllocator());
	reply.AddMember("CMD", value_t, reply.GetAllocator());

	auto iter = _process_callback_map.find(cmd);
	if (iter != _process_callback_map.end())
	{
		reply.AddMember("Status", int(PipeErrCode::PIPE_ERR_SUCCESS), reply.GetAllocator());
		const PipeProcessCallbackConfig& cb_config = iter->second;
		if (cb_config.sync)
		{
			cb_config.cb(in_data, reply);
			NamedPipeClient::GetInstance().WritePipe(reply);
		}
		else
		{
			String in_data_str, reply_str;
			{
				rapidjson::StringBuffer buffer;
				rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
				in_data.Accept(writer);
				in_data_str = buffer.GetString();
			}
			{
				rapidjson::StringBuffer buffer;
				rapidjson::Writer<rapidjson::StringBuffer> writer(buffer);
				reply.Accept(writer);
				reply_str = buffer.GetString();
			}
			TaskQueueService::GetInstance().AddTask([in_data_str, reply_str, cb_config]()
			{
				rapidjson::Document in_data, reply;
				in_data.Parse(in_data_str.c_str());
				reply.Parse(reply_str.c_str());
				cb_config.cb(in_data, reply);
				NamedPipeClient::GetInstance().WritePipe(reply);
			});
		}
	}
	else
	{
		reply.AddMember("Status", int(PipeErrCode::PIPE_ERR_PROC_NOT_FOUND), reply.GetAllocator());
		NamedPipeClient::GetInstance().WritePipe(reply);
	}
}

void PipeReadThreadTask::_ProcessHealthCheck(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	//reply to scheduler;
	const string& unique_id = in_data["CheckID"].GetString();
	rapidjson::Value value_t;
	value_t.SetString(unique_id.c_str(), reply.GetAllocator());
	reply.AddMember("CheckID", value_t, reply.GetAllocator());

	//send to kafka;
	EventHealthCheck* event_t = new EventHealthCheck(unique_id);
	//InitCollector::GetCollector()->PushSendRecord(event_t);
	// add by zxw on 20191107 添加空指针保护
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(event_t);
	else
	{
		EventRecordManager::GetInstance().RecycleEventRecord(event_t);
		WriteLog4cPlus(ERROR_LEVEL, L"_ProcessHealthCheck::InitCollector::GetCollector is null ");
	}

	WriteLog4cPlusA(INFO_LEVEL, "PipeReadThreadTask::_ProcessHealthCheck: CheckID = %s", unique_id.c_str());
}

void PipeReadThreadTask::_ProcessInitTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	STRING_VECTOR super_white_list;
	// mod by zxw 20191029 去掉clientscheduler白名单后面单独处理，为了通过和Kafka通信获取本机IP
	//super_white_list.push_back("clientscheduler.exe");
	// add by zxw on 20191107 添加ClientPro.exe、ProtecteClient.exe进白名单不处理自己程序信息
	super_white_list.push_back("ClientPro.exe");
	super_white_list.push_back("ProtecteClient.exe");
	//
	super_white_list.push_back("ETWData.exe");
	for (auto& val : in_data["TrustListConfig"].GetArray())
	{
		super_white_list.push_back(val.GetString());
		WriteLog4cPlusA(WARN_LEVEL, "PipeReadThreadTask::_ProcessInitTrustList: file_name = %s", val.GetString());
	}

	Filter::GetInstance().InitSuperWhiteList(super_white_list);
	WriteLog4cPlus(WARN_LEVEL, L"PipeReadThreadTask::_ProcessInitTrustList: size = %d", super_white_list.size());
}

void PipeReadThreadTask::_ProcessAddTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	STRING_VECTOR list_add;
	for (auto& val : in_data["TrustListAdd"].GetArray())
	{
		list_add.push_back(val.GetString());
	}
	Filter::GetInstance().AddSuperWhiteList(list_add);
	WriteLog4cPlus(WARN_LEVEL, L"PipeReadThreadTask::_ProcessAddTrustList: size = %d", list_add.size());
}

void PipeReadThreadTask::_ProcessRemoveTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	STRING_VECTOR list_remove;
	for (auto& val : in_data["TrustListRemove"].GetArray())
	{
		list_remove.push_back(val.GetString());
	}
	Filter::GetInstance().RemoveSuperWhiteList(list_remove);
	WriteLog4cPlus(WARN_LEVEL, L"PipeReadThreadTask::_ProcessRemoveTrustList: size = %d", list_remove.size());
}

void PipeReadThreadTask::_ProcessChangeTrustList(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	const String& file_name_s = in_data["FileNameSource"].GetString();
	const String& file_name_d = in_data["FileNameDestiny"].GetString();
	Filter::GetInstance().ChangeSuperWhiteList(file_name_s, file_name_d);
	WriteLog4cPlusA(WARN_LEVEL, "PipeReadThreadTask::_ProcessChangeTrustList: file_name_s = %s, file_name_d = %s", file_name_s.c_str(), file_name_d.c_str());
}

void PipeReadThreadTask::_ProcessChangeGear(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	CollectorGear target_gear = (CollectorGear)in_data["TargetGear"].GetInt();
	Filter::GetInstance().SetCollectorGear(target_gear);
	reply.AddMember("TargetGear", (int_32)target_gear, reply.GetAllocator());
	WriteLog4cPlus(WARN_LEVEL, L"PipeReadThreadTask::_ProcessChangeGear: target_gear = %d", (int)target_gear);
}

void PipeReadThreadTask::_ProcessParseAutorun(const rapidjson::Document& in_data, rapidjson::Document& reply)
{
	STRING_SET autorun_info;
	ToolFunctions::ParseAutorunInfo(autorun_info);
	
	STRING_VECTOR autorun_info_vec;
	std::copy(autorun_info.begin(), autorun_info.end(), std::back_inserter(autorun_info_vec));
	String autorun_info_join = StringUtil::Join(autorun_info_vec, 0, "|");
	EventAutorunInfo* ev = new EventAutorunInfo(autorun_info_join);
	// add by zxw on 20191107 添加空指针保护
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->PushSendRecord(ev);
	else
	{
		EventRecordManager::GetInstance().RecycleEventRecord(ev);
		WriteLog4cPlus(ERROR_LEVEL, L"_ProcessParseAutorun::InitCollector::GetCollector is null " );
	}

	WriteLog4cPlus(WARN_LEVEL, L"PipeReadThreadTask::_ProcessParseAutorun");
}

void PipeReadThreadTask::_ProcessUpdateClientIP(const rapidjson::Document & in_data, rapidjson::Document & reply)
{
	rapidjson::Value value_t;
	value_t.SetString(PIPE_PROC_UPDATE_CLIENT_IP, reply.GetAllocator());
	reply.AddMember("CMD", value_t, reply.GetAllocator());

	const string& localIP = Filter::GetInstance().GetLocalIP();
	value_t.SetString(localIP.c_str(), reply.GetAllocator());
	reply.AddMember("Client_ip", value_t, reply.GetAllocator());

	WriteLog4cPlusA(INFO_LEVEL, "PipeReadThreadTask::_ProcessUpdateClientIP repy update localIP = %s", localIP.c_str());
}

void PipeReadThreadTask::_ProcessRansomSuffixWhiteList(const rapidjson::Document & in_data, rapidjson::Document & reply)
{
    int is_terminate = 0;
	STRING_VECTOR suffix_white_list;
	for (auto& val : in_data["SUFFIX_LIST"].GetArray())
	{
		suffix_white_list.push_back(val.GetString());
		WriteLog4cPlusA(INFO_LEVEL, "PipeReadThreadTask::_ProcessRansomSuffixWhiteList: suffix_name = %s", val.GetString());
	}

    if (in_data.HasMember("Terminate") && in_data["Terminate"].IsInt()) {
        is_terminate = in_data["Terminate"].GetInt();
        WriteLog4cPlus(INFO_LEVEL, L"ThreadTaskPipeRead::_Pr_ProcessRansomSuffixWhiteListocess: is_terminate %d", is_terminate);
    }

	Filter::GetInstance().AddRansomSuffixWhiteList(suffix_white_list, is_terminate);
	WriteLog4cPlus(INFO_LEVEL, L"PipeReadThreadTask::_ProcessRansomSuffixWhiteList: size = %d", suffix_white_list.size());
}

void PipeReadThreadTask::_ProcessUpdateCustomRule(const rapidjson::Document & in_data, rapidjson::Document & reply)
{
    WriteLog4cPlus(INFO_LEVEL, L"PipeReadThreadTask::_ProcessUpdateCustomRule");
    std::unordered_map<EventIdentifier, std::set<SRule>> rule_matcher;
    if (public_json_interface::GetInstance().ParseRulebyDocument(in_data, rule_matcher))
    {
        rule_matcher::GetInstance().update_rule_map(rule_matcher);
    }    
}

void PipeReadThreadTask::_ProcessRuleMatchSwitch(const rapidjson::Document & in_data, rapidjson::Document & reply) 
{
    WriteLog4cPlus(INFO_LEVEL, L"PipeReadThreadTask::_ProcessRuleMatchSwitch");
    if (in_data.HasMember("RuleMatch") && in_data["RuleMatch"].IsString())
    {
        auto rule_match = in_data["RuleMatch"].GetString();
        Filter::GetInstance().RuleMatchSwitch(rule_match);
        WriteLog4cPlusA(INFO_LEVEL, "PipeReadThreadTask::_ProcessRuleMatchSwitch: rule_match = %s", rule_match);
    }
}

void PipeReadThreadTask::_ProcessCertificateList(const rapidjson::Document & in_data, rapidjson::Document & reply) 
{
    WriteLog4cPlus(INFO_LEVEL, L"PipeReadThreadTask::_ProcessCertificateList");
    std::vector<SCertificateResult> certificate_white_list;
    if (in_data.HasMember("CertificateList")) 
    {
        const rapidjson::Value& certArray = in_data["CertificateList"];
        if (certArray.IsArray())
        {
            for (int i = 0; i < certArray.Size(); ++i)
            {
                SCertificateResult scert;
                const rapidjson::Value& tmp = certArray[i];

                if (tmp.HasMember("ThumbPrit") && tmp["ThumbPrit"].IsString()) 
                {
                    scert.thumbPrint = tmp["ThumbPrit"].GetString();                   
                }
                if (tmp.HasMember("SubjectName") && tmp["SubjectName"].IsString()) 
                {
                    scert.subjectname = tmp["SubjectName"].GetString();
                }
                certificate_white_list.push_back(scert);
                WriteLog4cPlusA(DEBUG_LEVEL, "PipeReadThreadTask::CertificateList: ThumbPrit: %s", scert.thumbPrint.c_str());
            }
        }

        //Filter::GetInstance().RuleMatchSwitch(rule_match);
    }
}
