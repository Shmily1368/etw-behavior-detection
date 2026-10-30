#pragma once
#include "assist_macro.h"
#include <unordered_set>
#include <string>
#include <Windows.h>
#include "rwlock.h"
#include <boost/functional/hash.hpp>
#include "json_include/rapidjson/filereadstream.h"
#include "json_include/rapidjson/document.h"
#include "json_include/rapidjson/prettywriter.h"
#include "json_include/rapidjson/stringbuffer.h"

struct RansomFilter
{
	int param = -1;
	std::wstring chMD5 = L"";
	std::wstring chProcessName = L"";
	std::wstring chProcessPath = L"";
	std::wstring chProcessUser = L"";
	std::wstring chParentProcessName = L"";
	std::wstring chProcessCommandLine = L"";
	bool operator==(const RansomFilter& a) const {
		return (a.param == param) && (a.chMD5 == chMD5) && (a.chProcessName == chProcessName) && (a.chProcessPath == chProcessPath) && (a.chProcessUser == chProcessUser) && (a.chParentProcessName == chParentProcessName) && (a.chProcessCommandLine == chProcessCommandLine);
	}
};

inline std::size_t hash_value(const RansomFilter& filter) {
	auto seed = size_t{ 0 };
	boost::hash_combine(seed, filter.param);
	boost::hash_combine(seed, filter.chMD5);
	boost::hash_combine(seed, filter.chProcessName);
	boost::hash_combine(seed, filter.chProcessPath);
	boost::hash_combine(seed, filter.chProcessUser);
	boost::hash_combine(seed, filter.chParentProcessName);
	boost::hash_combine(seed, filter.chProcessCommandLine);
	return seed;
};


class RansomFilterRule
{
	SINGLETON_DEFINITION(RansomFilterRule);

private:
	RansomFilterRule() = default;
	~RansomFilterRule() = default;
public:
	void add_filter_set_by_file(const std::string& fileName);
	void add_filter_set_by_string(const std::string& strContent);
	bool ransom_rule_matcher(DWORD pid) const;
	
	bool white_rule_matcher(DWORD pid) const;
	bool black_rule_matcher(DWORD pid) const;
private:
	mutable RwLock _rule_lock;
	std::unordered_set<RansomFilter, boost::hash<RansomFilter>> _rule_matcher;
	bool parse_json(const rapidjson::Value& json, RansomFilter& filter) const;
	bool isMatch(const wstring& str, const wstring& patten) const;
	bool isMatchEx(const wstring& str, const wstring& patten, int param) const;
};

