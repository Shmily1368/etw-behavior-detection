#include "stdafx.h"
#include "FilterRule.h"
#include <boost/regex.hpp>
#include <fstream>
#include "tool_functions.h"
#include "process_event_info.h"
#include <boost/algorithm/string/predicate.hpp>


void RansomFilterRule::add_filter_set_by_file(const std::string& fileName)
{
	try {
		std::ifstream in(fileName);
		if (!in.is_open()) {
			WriteLog4cPlus(ERROR_LEVEL, L"add_filter_set_by_file open file failed,error: %d", GetLastError());
			return;
		}
		std::string json_content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
		in.close();

		add_filter_set_by_string(json_content);
	}
	catch (...) {
		WriteLog4cPlus(ERROR_LEVEL, L"add_filter_set_by_file catch exception,error: %d", GetLastError());
	}
}

void RansomFilterRule::add_filter_set_by_string(const std::string& strContent)
{
	try
	{
		rapidjson::Document dom;
		if (!dom.Parse(strContent.c_str()).HasParseError()) {

			rapidjson::Value filter;
			filter.Swap(dom);
			if (filter.HasMember("filter")) {
				filter = filter["filter"];
			}
			if (filter.HasMember("process") && filter["process"].IsArray())
			{
				const rapidjson::Value& arr = filter["process"];
				for (rapidjson::SizeType i = 0; i < arr.Size(); ++i) {
					RansomFilter rule;
					if (parse_json(arr[i], rule))
					{
						_rule_lock.WriteLock();
						_rule_matcher.emplace(std::move(rule));
						_rule_lock.WriteUnlock();
					}
				}
			}		
		}
	}
	catch (...)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ParseRulebyStr catch exception,error: %d", GetLastError());
	}
}

bool RansomFilterRule::ransom_rule_matcher(DWORD pid) const
{
	if (_rule_matcher.empty()) return false;
	auto iter = process_map::g_umapPid2ProcessInfo.find(pid);
	if (iter == process_map::g_umapPid2ProcessInfo.end()) return false;
	auto info = iter->second;
	auto ppid = info.parent_pid;
	std::wstring parentname = L"";
	auto pter = process_map::g_umapPid2ProcessInfo.find(ppid);
	if (pter != process_map::g_umapPid2ProcessInfo.end())
	{
		parentname = pter->second.process_name;
	}
	bool ret = false;
	for (auto&& item : _rule_matcher)
	{
		if (!isMatch(info.process_name, item.chProcessName)) continue;
		if (!isMatch(info.process_path, item.chProcessPath)) continue;
		if (!isMatchEx(info.commandline, item.chProcessCommandLine, item.param)) continue;
		if (!isMatch(info.user, item.chProcessUser)) continue;
		if (!isMatch(parentname, item.chParentProcessName)) continue;
		if (!isMatch(info.md5, item.chMD5)) continue;
		
		if (!ret) {
			ret = true;
			break;
		}
	}
	return ret;
}


bool RansomFilterRule::white_rule_matcher(DWORD pid) const
{
	auto iter = process_map::g_umapPid2ProcessInfo.find(pid);
	if (iter == process_map::g_umapPid2ProcessInfo.end()) return false;
	auto info = iter->second;
	auto ppid = info.parent_pid;
	std::wstring parentname = L"";
	auto pter = process_map::g_umapPid2ProcessInfo.find(ppid);
	if (pter != process_map::g_umapPid2ProcessInfo.end())
	{
		parentname = pter->second.process_name;
	}

	CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> RuleFilterProcess = ToolFunctions::GetMSBasicInfoNGEPRule()->m_niRuleFilterProcess;
	if (CMSBasicInfo_NGEPRuleMatcher::CheckProcess(RuleFilterProcess
		, info.process_name
		, info.process_path
		, info.commandline
		, info.md5
		, info.user
		, parentname) )
		return true;
	else
 		return false;
}

bool RansomFilterRule::black_rule_matcher(DWORD pid) const
{
	auto iter = process_map::g_umapPid2ProcessInfo.find(pid);
	if (iter == process_map::g_umapPid2ProcessInfo.end()) return false;
	auto info = iter->second;
	auto ppid = info.parent_pid;
	std::wstring parentname = L"";
	auto pter = process_map::g_umapPid2ProcessInfo.find(ppid);
	if (pter != process_map::g_umapPid2ProcessInfo.end())
	{
		parentname = pter->second.process_name;
	}

	CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> RuleBlackProcess = ToolFunctions::GetMSBasicInfoNGEPRule()->m_niRuleBlackProcess;
	if (CMSBasicInfo_NGEPRuleMatcher::CheckProcess(RuleBlackProcess, info.process_name, info.process_path, info.commandline, info.md5, info.user, parentname))
		return true;
	else
		return false;
}

bool RansomFilterRule::parse_json(const rapidjson::Value& json, RansomFilter& filter) const
{
	try
	{
		if (json.HasMember("param") && json["param"].IsString()) {
			filter.param = atoi(json["param"].GetString());
		}
		if (json.HasMember("md5") && json["md5"].IsString()) {
			filter.chMD5 = ToolFunctions::StringToWString(json["md5"].GetString());
		}
		if (json.HasMember("process_name") && json["process_name"].IsString()) {
			filter.chProcessName = ToolFunctions::StringToWString(json["process_name"].GetString());
		}
		if (json.HasMember("process_path") && json["process_path"].IsString()) {
			filter.chProcessPath = ToolFunctions::StringToWString(json["process_path"].GetString());
		}
		if (json.HasMember("process_commandline") && json["process_commandline"].IsString()) {
			filter.chProcessCommandLine = ToolFunctions::StringToWString(json["process_commandline"].GetString());
			if (filter.chProcessCommandLine.empty())
				filter.param = -1;
		}
		if (json.HasMember("process_user") && json["process_user"].IsString()) {
			filter.chProcessUser = ToolFunctions::StringToWString(json["process_user"].GetString());
		}
		if (json.HasMember("parent_process_name") && json["parent_process_name"].IsString()) {
			filter.chParentProcessName = ToolFunctions::StringToWString(json["parent_process_name"].GetString());
		}
	}
	catch (...)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"parse_json catch exception,error: %d", GetLastError());
		return false;
	}
	return true;
	
}

bool RansomFilterRule::isMatch(const wstring& str, const wstring& pattern) const
{
	if (pattern.empty()) 
		return true;
	boost::wsmatch m;
	boost::wregex e(pattern, boost::regex_constants::icase);
	if (boost::regex_search(str, m, e, boost::match_flag_type::match_stop))
	{
		return true;
	}
	return false;
}

bool RansomFilterRule::isMatchEx(const wstring& str, const wstring& pattern, int param) const
{
	if (pattern.empty() || param > 2 || param < 0)
		return true;
	bool ret = false;
	switch (param)
	{
	case 0:
		ret = boost::iequals(str, pattern);
		break;
	case 1:
		ret = boost::icontains(str, pattern);
		break;
	case 2:
		ret = !(boost::icontains(str, pattern));
		break;
	default:
		break;
	}
	return ret;
}