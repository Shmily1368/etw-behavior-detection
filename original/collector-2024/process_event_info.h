#pragma once
#include <Windows.h>
#include <unordered_map>
#include <string>
struct process_event_info
{
	ULONG64 start_QPCtime = 0;
	std::wstring md5 = L"";
	std::wstring process_name = L"";
	std::wstring process_path = L"";
	std::wstring commandline = L"";
	std::wstring user = L"";
	DWORD parent_pid = -1;
	bool m_bExisted = false;
	process_event_info() = default;
	explicit process_event_info(ULONG64 time) : start_QPCtime(time) {}
	void reset()
	{
		start_QPCtime = 0;
		md5 = L"";
		process_name = L"";
		process_path = L"";
		commandline = L"";
		user = L"";
		parent_pid = -1;
		m_bExisted = false;
	}
};

struct process_map
{
	static std::unordered_map<DWORD, process_event_info> g_umapPid2ProcessInfo;
};