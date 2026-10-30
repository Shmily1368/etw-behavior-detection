#pragma once
#include <Windows.h>
#include <unordered_set>
#include "event_record_manager.h"
#include <string>
#include "EtwEntropy/EtwEntropy/IEtwEntropy.h"

class RansomCheck
{
public:
	static void initDetectFlag();
	static bool getDetectFlag();
	static bool certificatepid(DWORD pid);
	static void checkPids(DWORD pid, const std::wstring& process_name, DWORD ppid, const std::wstring& pprocess_name);
	//not used
	//static void updateTocheck(DWORD pid, DWORD ppid);
	static bool checkRansomPid(DWORD pid);
	static void outputRansom(DWORD pid, const std::wstring& process_name, DWORD ppid, const std::wstring& pprocess_name);
	// public interfaces to cache
	static void removeSystemProcess(DWORD pid);
	static void addSystemProcess(DWORD pid);
	static void removeAbnormalProcess(DWORD pid);
	static void removeCheckProcess(DWORD pid);
	static void removeProcess(DWORD pid);
	static void addRansomWhiteList(DWORD pid);
	static void removeRansomWhiteList(DWORD pid);
	static bool queryRansomWhiteList(DWORD pid);
	static void addRansomBlackList(DWORD pid);
	static void removeRansomBlackList(DWORD pid);

	static ICEtwEntropy* m_IEtwEntropy;
private:
	static bool m_bInit;
	static bool m_bIsDetected;
	static bool m_bIsTerminate;
	static std::unordered_map<DWORD, std::unordered_set<DWORD>> m_umapAbPid2PPid;
	static std::unordered_set<DWORD> m_umapAbnormalProcess;
	static std::unordered_set<DWORD> m_umapSystemProcess;
	static std::unordered_set<DWORD> m_umapProcessToCheck;
	static const std::string m_strOutputPath;
	static std::unordered_set<DWORD> m_umapWhiteListRansom;
	static std::unordered_set<DWORD> m_umapBlackListRansom;
	static std::wstring injectFeature(const wstring& process_name1, const wstring& process_name2);

};

