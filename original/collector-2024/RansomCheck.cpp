#include "stdafx.h"
#include "RansomCheck.h"
#include "setting.h"
#include "init_collector_online_parse.h"
#include "tool_functions.h"
#include "thread_task_cerficate_image.h"
#include "filter.h"
#include "certificate_tool.h"
#include "FilterRule.h"

bool RansomCheck::m_bInit = false;
bool RansomCheck::m_bIsDetected = false;
bool RansomCheck::m_bIsTerminate = false;
std::unordered_map<DWORD, std::unordered_set<DWORD>> RansomCheck::m_umapAbPid2PPid;
std::unordered_set<DWORD> RansomCheck::m_umapAbnormalProcess;
std::unordered_set<DWORD> RansomCheck::m_umapSystemProcess;
std::unordered_set<DWORD> RansomCheck::m_umapProcessToCheck;
std::unordered_set<DWORD> RansomCheck::m_umapWhiteListRansom;
std::unordered_set<DWORD> RansomCheck::m_umapBlackListRansom;
const std::string RansomCheck::m_strOutputPath = "output\\output.out";
ICEtwEntropy* RansomCheck::m_IEtwEntropy = nullptr;

void RansomCheck::initDetectFlag()
{
	if (m_bInit) return;
	m_bIsDetected = Setting::GetInstance().enable_ransom_detector();
	m_bIsTerminate = Setting::GetInstance().enable_ransom_terminate();
	if (m_bIsDetected)
	{
		m_umapSystemProcess.insert(GetCurrentProcessId());  // 对本进程过滤
		RansomFilterRule::GetInstance().add_filter_set_by_file("rule.lst");
		m_IEtwEntropy = GetEtwEntropyInstance();
	}
}

bool RansomCheck::getDetectFlag()
{
	return m_bIsDetected;
}

bool RansomCheck::certificatepid(DWORD pid)
{
	const std::wstring& file_name = Filter::QurFullPath(pid);
	bool ret = false;
	if (!file_name.empty())
	{
		do
		{
			if (NULL != PathMatchSpec(file_name.c_str(), L"*\\System32\\*")
				|| NULL != PathMatchSpec(file_name.c_str(), L"*\\Windows\\*"))
			{
				RansomCheck::addRansomWhiteList(pid);
				ret = true;
				break;
			}
			EM_CertificateResult result = CertificateTool::VerifyEmbeddedSignature(file_name.c_str());

			if (ToolFunctions::isEndWith(file_name.c_str(), L"exe") || ToolFunctions::isEndWith(file_name.c_str(), L"EXE"))
			{
				if (result == EM_CertificateResult::CERTIFICATE_RESULT__NORMAL)
				{
					ret = true;
					RansomCheck::addRansomWhiteList(pid);
				}
			}
		} while (false);
	}
	return ret;
}

void RansomCheck::checkPids(DWORD pid, const std::wstring& process_name, DWORD ppid, const std::wstring& pprocess_name)
{
	if (m_umapSystemProcess.find(ppid) == m_umapSystemProcess.end())
	{
		if (m_umapAbnormalProcess.find(ppid) != m_umapAbnormalProcess.end())
		{
			auto iter = m_umapAbPid2PPid.find(ppid);
			bool flag = true;
			for (auto s : iter->second) {
				if (s != ULONG_MAX && m_umapWhiteListRansom.find(s) == m_umapWhiteListRansom.end())
				{
					flag = false;
					break;
				}
			}
			if (flag)
			{
				m_umapAbnormalProcess.erase(ppid);
				m_umapAbPid2PPid.erase(ppid);
			}
			else {
				if ((!RansomFilterRule::GetInstance().ransom_rule_matcher(pid)) && (!RansomFilterRule::GetInstance().white_rule_matcher(pid)))
				{
					outputRansom(pid, process_name, ppid, pprocess_name);
				}
			}
		}
		else {
			if (ppid != ULONG_MAX && m_umapBlackListRansom.find(ppid) == m_umapBlackListRansom.end() && (!RansomFilterRule::GetInstance().black_rule_matcher(ppid)))
			{
				if(m_umapWhiteListRansom.find(ppid) == m_umapWhiteListRansom.end() && !certificatepid(ppid))
				{
					m_umapAbnormalProcess.insert(pid);
					//abnormal_process.insert(ppid);
					if (m_umapAbPid2PPid.find(pid) == m_umapAbPid2PPid.end()) m_umapAbPid2PPid[pid] = std::unordered_set<DWORD>();
					m_umapAbPid2PPid[pid].insert(ppid);
				}
				else {
					m_umapWhiteListRansom.insert(pid);
				}
				if (m_umapProcessToCheck.find(pid) == m_umapProcessToCheck.end())
				{
					m_umapProcessToCheck.insert(pid);
				}
				if (m_umapProcessToCheck.find(ppid) == m_umapProcessToCheck.end())
				{
					m_umapProcessToCheck.insert(ppid);
				}
			}
		}
	}
}

//void RansomCheck::updateTocheck(DWORD pid, DWORD ppid)
//{
//	if (system_process.find(pid) != system_process.end())
//	{
//		if (process_tocheck.find(pid) == process_tocheck.end())
//		{
//			process_tocheck.insert(pid);
//		}
//		if (process_tocheck.find(ppid) == process_tocheck.end())
//		{
//			process_tocheck.insert(ppid);
//		}
//	}
//}

bool RansomCheck::checkRansomPid(DWORD pid)
{
	if (!m_bIsDetected) return false;
	bool bResult = m_umapProcessToCheck.find(pid) != m_umapProcessToCheck.end();
	//WriteLog4cPlusA(INFO_LEVEL, "checkRansomPid %d,%d", pid, bResult);
	return bResult;
}

std::wstring RansomCheck::injectFeature(const wstring& pprocess_name, const wstring& process_name)
{
	wstring feature = pprocess_name + L" inject into " + process_name;
	return feature;
}

void RansomCheck::outputRansom(DWORD pid, const std::wstring& process_name, DWORD ppid, const std::wstring& pprocess_name)
{
	DWORD dwMode = ToolFunctions::GetMode();

	auto pFunIsNormalMode = [&]()
		{
			return dwMode == OPERATION_MODE_NORAML;
		};

	GUID guid;
	CoCreateGuid(&guid);
	wstring feature = injectFeature(pprocess_name, process_name);
	EventRecord* event_record = EventRecordManager::GetInstance().ParseRansomDetectorEvent(pid, ppid, process_name, pprocess_name, feature, guid);
	if (event_record)
	{
		WriteLog4cPlus(INFO_LEVEL, L"check inject ransom, pid: %d ppid: %d process name: %s parent process name: %s", pid, ppid, process_name.c_str(), pprocess_name.c_str());
		InitCollector::GetCollector()->PushSendRecord(event_record);
	}
	auto iter = m_umapAbPid2PPid.find(ppid);
	if (iter != m_umapAbPid2PPid.end())
	{
		auto sets = iter->second;
		if (!sets.empty())
		{
			for (DWORD num : sets) {
				if (num != pid && num != ppid)
				{
					if (m_bIsTerminate && pFunIsNormalMode())
					{
						if (ToolFunctions::KillProcess(num)) {
							removeProcess(num);
						}
					}
				}
			}
		}
	}
	bool process_stopped = false;
	bool pprocess_stopped = false;
	if (m_bIsTerminate && pFunIsNormalMode())
	{
		process_stopped = ToolFunctions::KillProcess(pid);
		if (process_stopped)
		{
			removeProcess(pid);
		}
		pprocess_stopped = ToolFunctions::KillProcess(ppid);
		if (pprocess_stopped)
		{
			removeProcess(ppid);
		}
	}

	EventRecord* event_terminate = EventRecordManager::GetInstance().ParseRansomTerminateEvent(pid, process_name, m_bIsTerminate, process_stopped, guid);
	if (event_terminate) InitCollector::GetCollector()->PushSendRecord(event_terminate);
	EventRecord* pevent_terminate = EventRecordManager::GetInstance().ParseRansomTerminateEvent(ppid, pprocess_name, m_bIsTerminate, pprocess_stopped, guid);
	if (pevent_terminate) InitCollector::GetCollector()->PushSendRecord(pevent_terminate);


	if (Setting::GetInstance().enable_ransom_output())
	{
		ofstream write(m_strOutputPath, ios::app);
		write << "inject, pid: " << pid << " processname: " << ToolFunctions::WStringToString(process_name) << " ppid: " << ppid << " pprocessname: " << ToolFunctions::WStringToString(pprocess_name) << endl;
		write.close();
	}
}

void RansomCheck::removeSystemProcess(DWORD pid)
{
	if (!m_bIsDetected) return;
	m_umapSystemProcess.erase(pid);
}

void RansomCheck::addSystemProcess(DWORD pid)
{
	if (!m_bIsDetected) return;
	m_umapSystemProcess.insert(pid);
}

void RansomCheck::removeAbnormalProcess(DWORD pid)
{
	if (!m_bIsDetected || pid == -1) return;
	m_umapAbnormalProcess.erase(pid);
}

void RansomCheck::removeCheckProcess(DWORD pid)
{
	if (!m_bIsDetected || pid == -1) return;
	m_umapProcessToCheck.erase(pid);
}

void RansomCheck::removeProcess(DWORD pid)
{
	if (pid == -1) return;
	m_umapAbnormalProcess.erase(pid);
	m_umapProcessToCheck.erase(pid);
	m_umapSystemProcess.erase(pid);
	m_umapAbPid2PPid.erase(pid);
}


void RansomCheck::addRansomWhiteList(DWORD pid)
{
	m_umapWhiteListRansom.insert(pid);
}

void RansomCheck::removeRansomWhiteList(DWORD pid)
{
	m_umapWhiteListRansom.erase(pid);
}

bool RansomCheck::queryRansomWhiteList(DWORD pid)
{
	return m_umapWhiteListRansom.find(pid) != m_umapWhiteListRansom.end();
}

void RansomCheck::addRansomBlackList(DWORD pid)
{
	m_umapBlackListRansom.insert(pid);
}

void RansomCheck::removeRansomBlackList(DWORD pid)
{
	m_umapBlackListRansom.erase(pid);
}