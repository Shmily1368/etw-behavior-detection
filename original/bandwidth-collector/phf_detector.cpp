#include "stdafx.h"
#include <algorithm>
#include <iterator>
#include <thread>
#include "phf_detector.h"
#include "signature.h"
#include "tool_functions.h"
#include "string_util.h"
#include "init_collector.h"
#include "setting.h"
#include "filter.h"
#include "thread_task_manager.h"
#include "time_util.h"
#define api_num 2863
using namespace std;

/*
optimize,fix chips
1.使用单例代替成员变量的static;
2.所有对map的增删改成封装成read/write/del操作;
3.对多个map的依次赋值如果存在共性放入一个函数中;
*/
//
static std::unordered_map<DWORD, vector<int> > process_to_precallstack;
static std::unordered_map<DWORD, string> thread_to_apis;
std::unordered_map<DWORD, std::pair<DWORD, ULONG64>> pid_to_thread;  //0
static std::unordered_map<DWORD, std::pair<DWORD, ULONG64>> pid_to_thread_full;  //1
static std::unordered_map<DWORD, std::pair<DWORD, ULONG64>> pid_to_thread_top;   //2
static std::unordered_set<int> create_pipe_pids;
static std::unordered_set<int> detected_remoteshell;
static std::unordered_set<string> lcsdetect_api_screengrab;
static std::unordered_set<string> lcsdetect_api_processinject;
static std::unordered_set<string> lcsdetect_api_keylogger;
static std::unordered_set<string> lcsdetect_api_reflective;

static ULONG64 check_timestamp;
static std::unordered_map<DWORD, ULONG64> parent_process_create;
static std::unordered_map<DWORD, ULONG64> parent_process_end;
std::unordered_map<DWORD, int> PhfDetector::thread_2_keyloggercout_map;
//KeyloggerProcessSet PhfDetector::keylogger_process_cache;
KeyloggerProcessSet PhfDetector::keylogger_thread_cache;
static std::unordered_map<string, int> api2index_map;
static std::unordered_map<string, int> allapi2index_map;
static std::vector<std::vector<int> > callstack_vec;
static std::unordered_map<DWORD, vector<int> > process_to_apis_modern;  //0
static std::unordered_map<DWORD, string > process_to_apis_modern_full;  //1
static std::unordered_map<DWORD, string > process_to_apis_modern_top;  //2
static std::unordered_map<DWORD, set<int> > process_to_apigroups;




#ifdef USE_RAW_SIGNATURE

STRING_VECTOR_VECTOR keylogger_sigs =
{
   {
		//win7
		"GetKeyState",
		"GetKeyboardState",
		"GetAsyncKeyState",
		"NtUserGetKeyState",		//Win10 API;
		"NtUserGetKeyboardState"	//Win10 API;
	}
};

STRING_VECTOR_VECTOR screengrab_sigs =
{
	{
			"GetDC",   // may be CreateDCA is better 
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObject",
			"BitBlt"
	},
	//{
	//		"GetDC",
	//		"CreateCompatibleDC",
	//		"CreateCompatibleBitmap",
	//		"SelectObject",
	//		"BitBlt",
	//		"SelectObject",
	//		"DeleteDC",
	//		"ReleaseDC",
	//		"DeleteObject"
	//},
	{
			"GdipCreateBitmapFromScan0",
			"GdipGetImageThumbnail",
			"GdipCloneBitmapAreaI"
	},
	{
			"GetDC",
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObject",
			"StretchBlt"
	},
	// Win10
	{
			"NtUserGetDC",   // may be CreateDCA is better 
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObject",
			"BitBlt"
	},
	{
			"NtUserGetDC",
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObject",
			"StretchBlt"
	},
	{
			"NtUserGetDC",   // may be CreateDCA is better 
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObjectImpl",
			"BitBlt"
	},
	{
			"NtUserGetDC",
			"CreateCompatibleDC",
			"CreateCompatibleBitmap",
			"SelectObjectImpl",
			"StretchBlt"
	},
	{
			"NtUserGetDC",
			"CreateCompatibleDC",
			"CreateDIBSection",
			"SelectObjectImpl",
			"StretchBlt"
	},
	{
			"NtUserGetDC",
			"CreateCompatibleDC",
			"CreateDIBSection",
			"SelectObject",
			"StretchBlt"
	}
};

STRING_VECTOR_VECTOR processinjection_sigs =
{  //processstart Event
   // CreateProcess can also get handle of process
   // NovaLite v3.0 present
   {
	 "VirtualAllocEx",
	 "WriteProcessMemory",
   },

   {
	 "OpenProcess",
	 "VirtualAllocEx",
	 "WriteProcessMemory",
	 //CreateRemoteThread can be represent by ThreadStart Event,related by detector
   }
};

#else

STRING_VECTOR_VECTOR keylogger_sigs;
STRING_VECTOR_VECTOR screengrab_sigs;
STRING_VECTOR_VECTOR processinjection_sigs;
STRING_SET audiorecord_sigs;
STRING_SET remotedesktop_sigs;
STRING_SET remoteshell_sigs;
STRING_VECTOR_VECTOR reflective_sigs;

#endif // USE_RAW_SIGNATURE;
std::unordered_map<DWORD, int> process_to_str_len[6];

PhfDetector::PhfDetector()
	: _detect_phf_flag(false)
{
	int m = Setting::GetInstance().phf_method();
	String log_filename = TimeUtil::NowString() + ".out";
	switch (m)
	{
	case 0:
		if (Setting::GetInstance().step_by_step()) log_filename = "phf_s_" + log_filename;
		else log_filename = "phf_" + log_filename;
		statistic_file = fopen(log_filename.c_str(), "w+");
		break;
	case 1:
		log_filename = "full_" + log_filename;
		statistic_file = fopen(log_filename.c_str(), "w+");
		break;
	case 2:
		log_filename = "top_" + log_filename;
		statistic_file = fopen(log_filename.c_str(), "w+");
		break;
	case 3:
		statistic_file = nullptr;
		break;
	default:
		break;
	}
	
}

PhfDetector::~PhfDetector()
{

}

void PhfDetector::Init()
{
#ifndef USE_RAW_SIGNATURE

	//String phf_signature_folder = InitCollector::GetCollector()->GetDetectorMode() == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK ?
	//	"phf_signature_callstack\\" : "phf_signature_syscall\\";
	String phf_signature_folder = InitCollector::GetCollector()->GetDetectorMode() == LocalDetectorMode::LOCAL_DETECTOR_MODE__CALLSTACK ?
		"phf_signature\\" : "phf_signature_syscall\\";

	std::fstream fp;
	String read_str;

	//keylogger;
	//fp.open(phf_signature_folder + "keylogger_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_KEYLOGGER_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			keylogger_sigs.push_back(sig_vector);
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open keylogger_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);

	//screengrab;
	//fp.open(phf_signature_folder + "screengrab_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_SCREENGRAB_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			screengrab_sigs.push_back(sig_vector);
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open screengrab_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);


	//processinjection;
	//fp.open(phf_signature_folder + "processinjection_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_PROCESSINJECTION_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			processinjection_sigs.push_back(sig_vector);
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open screengrab_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);


	//audiorecord;
	//fp.open(phf_signature_folder + "audiorecord_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_AUDIORECORD_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			std::copy(sig_vector.begin(), sig_vector.end(), inserter(audiorecord_sigs, audiorecord_sigs.begin()));
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open audiorecord_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);


	//remotedesktop;
	//fp.open(phf_signature_folder + "remotedesktop_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_REMOTEDESKTOP_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			std::copy(sig_vector.begin(), sig_vector.end(), inserter(remotedesktop_sigs, remotedesktop_sigs.begin()));
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open remotedesktop_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);


	//remoteshell;
	//fp.open(phf_signature_folder + "remoteshell_signature", ios::in | ios::binary);
	// add by zxw on 20191107 隐藏文件信息
	fp.open(phf_signature_folder + PHF_REMOTESHELL_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open())
	{
		while (getline(fp, read_str))
		{
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			std::copy(sig_vector.begin(), sig_vector.end(), inserter(remoteshell_sigs, remoteshell_sigs.begin()));
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open remoteshell_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);

	fp.open(phf_signature_folder + PHF_REFLECTIVE_SIGNATURE, ios::in | ios::binary);
	if (fp.is_open()) {
		while (getline(fp, read_str)) {
			STRING_VECTOR sig_vector;
			StringUtil::split(ToolFunctions::DecryptStr(read_str), '|', sig_vector);
			reflective_sigs.push_back(sig_vector);
		}
		fp.close();
	}
	else
		LoggerRecord::WriteLog(L"PhfDetector::Init open keylogger_signature failed, code = " + std::to_wstring(GetLastError()), LogLevel::ERR);

#endif // USE_RAW_SIGNATURE;

	for (int i = 0; i < keylogger_sigs.size(); i++)
	{
		for (vector<string>::const_iterator iter = (keylogger_sigs[i]).cbegin(); iter != (keylogger_sigs[i]).cend(); iter++)
		{
			lcsdetect_api_keylogger.insert(*iter);
		}
	}

	for (int i = 0; i < screengrab_sigs.size(); i++)
	{
		for (vector<string>::const_iterator iter = (screengrab_sigs[i]).cbegin(); iter != (screengrab_sigs[i]).cend(); iter++)
		{
			lcsdetect_api_screengrab.insert(*iter);
		}
	}

	for (int i = 0; i < processinjection_sigs.size(); i++)
	{
		for (vector<string>::const_iterator iter = (processinjection_sigs[i]).cbegin(); iter != (processinjection_sigs[i]).cend(); iter++)
		{
			lcsdetect_api_processinject.insert(*iter);
		}
	}
	// add by zxw on 20200619 reflective loadin
	for (int i = 0; i < reflective_sigs.size(); i++) {
		for (vector<string>::const_iterator iter = (reflective_sigs[i]).cbegin(); iter != (reflective_sigs[i]).cend(); iter++) {
			lcsdetect_api_reflective.insert(*iter);
		}
	}
}

int lcs(std::vector<string> &X, vector<string> &Y)
{
	vector<vector<int>> L(X.size() + 1, vector<int>(Y.size() + 1));
	int m = (int)X.size();
	int n = (int)Y.size();
	//int L[m + 1][n + 1];
	int i, j;
	//unordered_set<string> uniq_apis_in_trace;
	/* Following steps build L[m+1][n+1] in bottom up fashion. Note
	   that L[i][j] contains length of LCS of X[0..i-1] and Y[0..j-1] */
	for (i = 0; i <= m; i++)
	{
		/*if (i != m)
			uniq_apis_in_trace.insert(X[i]);*/
		for (j = 0; j <= n; j++)
		{
			if (i == 0 || j == 0)
				L[i][j] = 0;

			else if (X[i - 1] == Y[j - 1])
				L[i][j] = L[i - 1][j - 1] + 1;

			else
				L[i][j] = max(L[i - 1][j], L[i][j - 1]);
		}
	}

	/* L[m][n] contains length of LCS for X[0..n-1] and Y[0..m-1] */
	return L[m][n];
}

int converage(std::unordered_set<string>&X, std::unordered_set<string>&Y, int & type)
{
	int count_time = 0;
	type = (int)X.size();

	for (unordered_set<string>::iterator it = Y.begin(); it != Y.end(); it++)
	{
		if (X.count(*it) != 0)
		{
			type--;
			count_time++;
		}
	}
	return count_time;
}

void CalculateApiDetail(const std::string &str, std::vector<string> &screengrab_api, std::vector<string> &processinject_api, int& keystate_count)
{
	STRING_VECTOR vec;
	StringUtil::split(str, ',', vec);

	bool flag = false;
	for (auto iter = vec.begin(); iter != vec.end(); iter++)
	{
		if (lcsdetect_api_keylogger.find(*iter) != lcsdetect_api_keylogger.end())
		{
			keystate_count++;
		}
		else if (lcsdetect_api_screengrab.find(*iter) != lcsdetect_api_screengrab.end())
		{
			screengrab_api.push_back(*iter);
		}
		else if (lcsdetect_api_processinject.find(*iter) != lcsdetect_api_processinject.end())
		{
			if (*iter == "WriteProcessMemory")
				flag = true;
			processinject_api.push_back(*iter);
		}
	}

	if (!flag)
		vector<string>().swap(processinject_api);

	return;
}

bool ReflectiveApiCounts(KeyloggerApiDataQueue api_queue, int &apicounts)
{
	bool res = false;
	int couts = 0;
	int reflectice_api[5] = { 0 };
	while (api_queue.size() > 0)
	{
		auto iter = api_queue.front();
		auto callstack = iter.api_name;
		if (callstack == "VirtualAlloc") {
			reflectice_api[0]++;
		}
		else if (callstack == "VirtualLock") {
			reflectice_api[1]++;
		}
		else if (callstack == "ZwFlushInstructionCache") {
			reflectice_api[2]++;
			res = true;
		}
		else if (callstack == "VirtualProtect") {
			reflectice_api[3]++;
		}
		else if (callstack == "RtlAllocateHeap") {
			reflectice_api[4]++;
		}

		api_queue.pop();
	}

	for (int i = 0; i < 5; i++)
	{
		if (reflectice_api[i] > 0)
		{
			couts++;
		}
	}
	apicounts = couts;
	return res;
}

//process must start before injection
void PhfDetector::NotifyProcessStart(DWORD ppid, std::wstring imageFileName, ULONG64 timestamp)
{
	if (imageFileName.find(L"cmd.exe") != std::wstring::npos && create_pipe_pids.count(ppid) != 0)
	{
		detected_remoteshell.insert(ppid);
	}
	parent_process_create[ppid] = timestamp;
}

void PhfDetector::NotifyProcessEnd(DWORD ppid, ULONG64 timestamp)
{
	parent_process_end[ppid] = timestamp;
	//keylogger_process_cache.erase(ppid);
}

void PhfDetector::NotifyThreadEnd(DWORD ttid)
{
	keylogger_thread_cache.erase(ttid);
}

void PhfDetector::OutputDetectPhf()
{
	if (!_detect_phf_flag)	return;

	_detect_phf_flag = false;

	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);

	if (EventRecord::frequency.QuadPart != 0)
	{
		ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart) * 10000000.0); //100-ns 
		check_timestamp = (EventRecord::start_systemtime + intervaltime) * 100; //1 * 100ns = 100ns 
	}

	for (auto iter = process_to_apis_modern.begin(); iter != process_to_apis_modern.end();)
	{
		DWORD pid = iter->first;
		if (pid_to_thread.count(pid) == 0)
		{
			iter++;
			continue;
		}
		DWORD tid = pid_to_thread[pid].first;
		ULONG64 timestamp = pid_to_thread[pid].second;
		int sum = 0;
		for (int num : iter->second) {
			sum += num;
		}
		if (sum == 0) continue;

		string s = "";
		for (int i = 0; i < iter->second.size(); i++) {
			if (iter->second[i] != 0) {
				if (!s.empty()) s += ",";
				s += to_string(i) + "_";
				if (iter->second[i] == sum)
				{
					s += "1";
				}
				else
				{
					double tt = (double)iter->second[i] / (double)sum;
					double t = double(round(tt * 10000)) / 10000;
					string ss = to_string(t);
					ss = ss.substr(0, ss.find_last_not_of('0') + 1);
					s += ss;
				}
			}
		}
		EventRecordCallstack* ev_phf = new EventRecordCallstack(pid, tid, timestamp);
		ev_phf->SetLabel(s);
		ev_phf->QPCtimeToSystime();
		//output
		pid_to_thread.erase(pid);
		if (process_to_precallstack.count(pid) != 0)process_to_precallstack.erase(pid);
		if (process_to_apigroups.count(pid) != 0) process_to_apigroups.erase(pid);
		process_to_apis_modern.erase(iter++);

		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(ev_phf);
		else
		{
			EventRecordManager::GetInstance().RecycleEventRecord(ev_phf);
			LoggerRecord::WriteLog(L"ProcessSystemCall InitCollector::GetCollector is null ", LogLevel::ERR);
		}
	}
	process_to_precallstack.clear();
	process_to_apigroups.clear();
	for (auto iter = parent_process_end.begin(); iter != parent_process_end.end();)
	{
		if (check_timestamp - iter->second < 12000000000) {
			iter++;
			continue;
		}
		if (parent_process_create.count(iter->first))
		{
			if (parent_process_create[iter->first] < iter->second)
			{
				parent_process_create.erase(iter->first);
			}
			parent_process_end.erase(iter++);
		}
		iter++;
	}
}

void PhfDetector::OutputDetectFullWithoutVec()
{
	if (!_detect_phf_flag)	return;
	_detect_phf_flag = false;
	for (auto iter = process_to_apis_modern_full.begin(); iter != process_to_apis_modern_full.end(); )
	{
		string s = "";
		auto pid = iter->first;
		auto t = pid_to_thread_full.find(pid);
		DWORD tid = 0;
		ULONG64 timestamp = 0;
		if (t != pid_to_thread_full.end())
		{
			tid = (t->second).first;
			timestamp = (t->second).second;
			pid_to_thread_full.erase(t);
		}
		//s += to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + "," + iter->second + ";";
		s = iter->second;
		EventRecordCallstack* ev_phf = new EventRecordCallstack(pid, tid, timestamp);
		ev_phf->SetLabel(s);
		ev_phf->QPCtimeToSystime();
		process_to_apis_modern_full.erase(iter++);
		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(ev_phf);
		else
		{
			EventRecordManager::GetInstance().RecycleEventRecord(ev_phf);
		}
	}

	pid_to_thread_full.clear();
	std::unordered_map<DWORD, std::pair<DWORD, ULONG64>>().swap(pid_to_thread_full);
	process_to_apis_modern_full.clear();
	unordered_map<DWORD, string >().swap(process_to_apis_modern_full);
}

void PhfDetector::OutputDetectTop()
{
	if (!_detect_phf_flag)	return;
	_detect_phf_flag = false;
	for (auto iter = process_to_apis_modern_top.begin(); iter != process_to_apis_modern_top.end(); )
	{
		string s = "";
		auto pid = iter->first;
		auto t = pid_to_thread_top.find(pid);
		DWORD tid = 0;
		ULONG64 timestamp = 0;
		if (t != pid_to_thread_top.end())
		{
			tid = (t->second).first;
			timestamp = (t->second).second;
			pid_to_thread_top.erase(t);
		}
		//s += to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + "," + iter->second + ";";
		s = iter->second;
		EventRecordCallstack* ev_phf = new EventRecordCallstack(pid, tid, timestamp);
		ev_phf->SetLabel(s);
		ev_phf->QPCtimeToSystime();
		process_to_apis_modern_top.erase(iter++);
		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(ev_phf);
		else
		{
			EventRecordManager::GetInstance().RecycleEventRecord(ev_phf);
		}
	}

	pid_to_thread_top.clear();
	std::unordered_map<DWORD, std::pair<DWORD, ULONG64>>().swap(pid_to_thread_top);
	process_to_apis_modern_top.clear();
	unordered_map<DWORD, string >().swap(process_to_apis_modern_top);
}

void PhfDetector::OutputDetectNo()
{
	return;
}

void PhfDetector::StatisticPhf()
{

	if (!_detect_phf_flag)	return;

	_detect_phf_flag = false;

	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);

	if (EventRecord::frequency.QuadPart != 0)
	{
		ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart) * 10000000.0); //100-ns 
		check_timestamp = (EventRecord::start_systemtime + intervaltime) * 100; //1 * 100ns = 100ns 
	}
	string str = "";
	for (auto iter = process_to_apis_modern.begin(); iter != process_to_apis_modern.end();)
	{
		DWORD pid = iter->first;
		if (pid_to_thread.count(pid) == 0)
		{
			iter++;
			continue;
		}
		DWORD tid = pid_to_thread[pid].first;
		ULONG64 timestamp = pid_to_thread[pid].second;
		int sum = 0;
		for (int num : iter->second) {
			sum += num;
		}
		if (sum == 0) continue;

		string s = "";
		for (int i = 0; i < iter->second.size(); i++) {
			if (iter->second[i] != 0) {
				if (!s.empty()) s += ",";
				s += to_string(i) + "_";
				if (iter->second[i] == sum)
				{
					s += "1";
				}
				else
				{
					double tt = (double)iter->second[i] / (double)sum;
					double t = double(round(tt * 10000)) / 10000;
					string ss = to_string(t);
					ss = ss.substr(0, ss.find_last_not_of('0') + 1);
					s += ss;
				}
			}
		}
		str += to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + "," + s + ";";
		//output
		pid_to_thread.erase(pid);
		if (process_to_precallstack.count(pid) != 0)process_to_precallstack.erase(pid);
		if (process_to_apigroups.count(pid) != 0) process_to_apigroups.erase(pid);
		process_to_apis_modern.erase(iter++);
	}
	process_to_precallstack.clear();
	process_to_apigroups.clear();

	for (auto iter = parent_process_end.begin(); iter != parent_process_end.end();)
	{
		if (check_timestamp - iter->second < 12000000000) {
			iter++;
			continue;
		}
		if (parent_process_create.count(iter->first))
		{
			if (parent_process_create[iter->first] < iter->second)
			{
				parent_process_create.erase(iter->first);
			}
			parent_process_end.erase(iter++);
		}
		iter++;
	}
	fprintf(statistic_file, "%d\n", str.size());
	cout << "method 0, with out step by step: " << str.size() << endl;
	fflush(statistic_file);
}

void PhfDetector::StatisticPhfStep()
{

	if (!_detect_phf_flag)	return;

	_detect_phf_flag = false;

	int count[7] = { 0 };   //记录大小
	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);

	if (EventRecord::frequency.QuadPart != 0)
	{
		ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart) * 10000000.0); //100-ns 
		check_timestamp = (EventRecord::start_systemtime + intervaltime) * 100; //1 * 100ns = 100ns 
	}
	//string str = "";
	for (auto iter = process_to_apis_modern.begin(); iter != process_to_apis_modern.end();)
	{
		DWORD pid = iter->first;
		if (pid_to_thread.count(pid) == 0)
		{
			iter++;
			continue;
		}
		DWORD tid = pid_to_thread[pid].first;
		ULONG64 timestamp = pid_to_thread[pid].second;
		int sum = 0;
		for (int num : iter->second) {
			sum += num;
		}
		if (sum == 0) continue;

		string s = "";
		for (int i = 0; i < iter->second.size(); i++) {
			if (iter->second[i] != 0) {
				if (!s.empty()) s += ",";
				s += to_string(i) + "_";
				if (iter->second[i] == sum)
				{
					s += "1";
				}
				else
				{
					double tt = (double)iter->second[i] / (double)sum;
					double t = double(round(tt * 10000)) / 10000;
					string ss = to_string(t);
					ss = ss.substr(0, ss.find_last_not_of('0') + 1);
					s += ss;
				}
			}
		}

		string sinfo = to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + ",";
		count[6] += sinfo.size() + s.size() + 1;
		for (int i = 0; i < 6; i++)
		{
			if (process_to_str_len[i].count(pid) != 0)
			{
				count[i] += sinfo.size() + process_to_str_len[i][pid];
				process_to_str_len[i].erase(pid);
			}
		}
		
		pid_to_thread.erase(pid);
		if (process_to_precallstack.count(pid) != 0)process_to_precallstack.erase(pid);
		if (process_to_apigroups.count(pid) != 0) process_to_apigroups.erase(pid);
		process_to_apis_modern.erase(iter++);
	}
	for (int i = 0; i < 6; i++)
	{
		for (auto iter = process_to_str_len[i].begin(); iter != process_to_str_len[i].end();)
		{
			DWORD pid = iter->first;
			if (pid_to_thread.count(pid) == 0)
			{
				iter++;
				continue;
			}
			DWORD tid = pid_to_thread[pid].first;
			ULONG64 timestamp = pid_to_thread[pid].second;
			string sinfo = to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + ",";
			count[i] += sinfo.size() + process_to_str_len[i][pid];
			process_to_str_len[i].erase(iter++);
		}
	}
	for (int i = 0; i < 6; i++)
	{
		process_to_str_len[i].clear();
	}
	pid_to_thread.clear();
	process_to_apis_modern.clear();
	process_to_precallstack.clear();
	process_to_apigroups.clear();

	for (auto iter = parent_process_end.begin(); iter != parent_process_end.end();)
	{
		if (check_timestamp - iter->second < 12000000000) {
			iter++;
			continue;
		}
		if (parent_process_create.count(iter->first))
		{
			if (parent_process_create[iter->first] < iter->second)
			{
				parent_process_create.erase(iter->first);
			}
			parent_process_end.erase(iter++);
		}
		iter++;
	}
	cout << "method 0, with step by step: ";
	for (int i = 0; i < 7; i++)
	{
		fprintf(statistic_file, "%d   ", count[i]);
		fflush(statistic_file);
		cout << count[i] << "   ";
	}
	cout << endl;
	fprintf(statistic_file, "\n");
	fflush(statistic_file);
	
}

void PhfDetector::StatisticFull()
{
	if (!_detect_phf_flag)	return;
	_detect_phf_flag = false;
	string s = "";
	for (auto iter = process_to_apis_modern_full.begin(); iter != process_to_apis_modern_full.end(); )
	{
		auto pid = iter->first;
		auto t = pid_to_thread_full.find(pid);
		DWORD tid = 0;
		ULONG64 timestamp = 0;
		if (t != pid_to_thread_full.end())
		{
			tid = (t->second).first;
			timestamp = (t->second).second;
			pid_to_thread_full.erase(t);
		}
		s += to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + "," + iter->second + ";";
		//s = iter->second;
		process_to_apis_modern_full.erase(iter++);
	}
	fprintf(statistic_file, "%d\n", s.size());
	fflush(statistic_file);
	cout << "method 1(full): " << s.size() << endl;
	pid_to_thread_full.clear();
	std::unordered_map<DWORD, std::pair<DWORD, ULONG64>>().swap(pid_to_thread_full);
	process_to_apis_modern_full.clear();
	unordered_map<DWORD, string >().swap(process_to_apis_modern_full);
}

void PhfDetector::StatisticTop()
{
	if (!_detect_phf_flag)	return;
	_detect_phf_flag = false;
	string s = "";
	for (auto iter = process_to_apis_modern_top.begin(); iter != process_to_apis_modern_top.end(); )
	{
		auto pid = iter->first;
		auto t = pid_to_thread_top.find(pid);
		DWORD tid = 0;
		ULONG64 timestamp = 0;
		if (t != pid_to_thread_top.end())
		{
			tid = (t->second).first;
			timestamp = (t->second).second;
			pid_to_thread_top.erase(t);
		}
		s += to_string(pid) + "," + to_string(timestamp) + "," + to_string(tid) + "," + iter->second + ";";
		process_to_apis_modern_top.erase(iter++);
	}
	fprintf(statistic_file, "%d\n", s.size());
	fflush(statistic_file);
	cout << "method 2(top): " << s.size() << endl;
	pid_to_thread_top.clear();
	std::unordered_map<DWORD, std::pair<DWORD, ULONG64>>().swap(pid_to_thread_top);
	process_to_apis_modern_top.clear();
	unordered_map<DWORD, string >().swap(process_to_apis_modern_top);
}

void PhfDetector::StatisticNo()
{
	return;
}

void PhfDetector::ParseThread2ApisFullWithVec(EventRecordCallstack* event_record)
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	const vector<int> callstack = event_record->get_vec_callstack_();
	if (callstack.empty())
	{
		return;
	}
	if (process_to_precallstack.count(process_id) == 0)
	{
		vector<int> t;
		process_to_precallstack[process_id] = t;
	}

	if (process_to_apigroups.count(process_id) == 0)
	{
		set<int> t;
		process_to_apigroups[process_id] = t;
	}

	vector<int> precallstack = process_to_precallstack[process_id];
	if (isRepetitiveCallstack(callstack, precallstack))
	{
		return;
	}

	if (!precallstack.empty() && precallstack[0] != callstack[0])
	{
		if (process_to_apis_modern.count(process_id) != 0)
		{
			for (int api : process_to_apigroups[process_id])
				process_to_apis_modern[process_id][api]++;
		}
		else
		{
			vector<int> process_callstack(api_num, 0);
			for (int api : process_to_apigroups[process_id])
			{
				process_callstack[api]++;
			}
			process_to_apis_modern[process_id] = process_callstack;
			pid_to_thread[process_id] = std::make_pair(thread_id, event_record->get_time_stamp_());
		}
		process_to_apigroups[process_id].clear();
	}
	else
	{
		for (int api : callstack)
		{
			process_to_apigroups[process_id].insert(api);
		}
	}
	precallstack.clear();
	for (int api : callstack)  precallstack.push_back(api);
	process_to_precallstack[process_id] = precallstack;
}

void PhfDetector::ParseThread2ApisFullWithVecStep(EventRecordCallstack* event_record)
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	const vector<int> callstack = event_record->get_vec_callstack_();
	if (callstack.empty())
	{
		return;
	}
	if (process_to_precallstack.count(process_id) == 0)
	{
		vector<int> t;
		process_to_precallstack[process_id] = t;
	}

	if (process_to_apigroups.count(process_id) == 0)
	{
		set<int> t;
		process_to_apigroups[process_id] = t;
	}

	vector<int> precallstack = process_to_precallstack[process_id];
	if (isRepetitiveCallstack(callstack, precallstack))
	{
		return;
	}
	else {
		string s = "";
		for (int call : callstack)
		{
			s += to_string(call) + ",";
		}
		if (process_to_str_len[5].count(process_id) == 0)
		{
			process_to_str_len[5][process_id] = s.size();
		}
		else
		{
			process_to_str_len[5][process_id] += s.size();
		}
	}

	if (!precallstack.empty() && precallstack[0] != callstack[0])
	{
		if (process_to_apis_modern.count(process_id) != 0)
		{
			for (int api : process_to_apigroups[process_id])
				process_to_apis_modern[process_id][api]++;
		}
		else
		{
			vector<int> process_callstack(api_num, 0);
			for (int api : process_to_apigroups[process_id])
			{
				process_callstack[api]++;
			}
			process_to_apis_modern[process_id] = process_callstack;
			if(pid_to_thread.count(process_id) == 0)pid_to_thread[process_id] = std::make_pair(thread_id, event_record->get_time_stamp_());
		}
		process_to_apigroups[process_id].clear();
	}
	else
	{
		for (int api : callstack)
		{
			process_to_apigroups[process_id].insert(api);
		}
	}
	precallstack.clear();
	for (int api : callstack)  precallstack.push_back(api);
	process_to_precallstack[process_id] = precallstack;
}

void PhfDetector::ParseThread2ApisFullWithoutVec(EventRecordCallstack* event_record)
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	string callstack = event_record->get_callstack_();
	if (callstack.length() == 0 || strstr(callstack.c_str(), "NOOAPI") != nullptr ||
		strstr(callstack.c_str(), "NOMODULE") != nullptr ||
		strstr(callstack.c_str(), "NOAPI") != nullptr)
	{
		return;
	}
	if (process_to_apis_modern_full.count(process_id) != 0)
	{
		process_to_apis_modern_full[process_id].append("," + callstack);
	}
	else
	{
		process_to_apis_modern_full[process_id] = callstack;
		pid_to_thread_full[process_id] = std::make_pair(thread_id, event_record->get_time_stamp_());
	}
}

void PhfDetector::ParseThread2ApisTop(EventRecordCallstack* event_record)
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	string callstack = event_record->get_callstack_();
	if (callstack.length() == 0 || strstr(callstack.c_str(), "NOOAPI") != nullptr ||
		strstr(callstack.c_str(), "NOMODULE") != nullptr ||
		strstr(callstack.c_str(), "NOAPI") != nullptr)
	{
		return;
	}
	if (process_to_apis_modern_top.count(process_id) != 0)
	{
		process_to_apis_modern_top[process_id].append("," + callstack);
	}
	else
	{
		process_to_apis_modern_top[process_id] = callstack;
		pid_to_thread_top[process_id] = std::make_pair(thread_id, event_record->get_time_stamp_());
	}
}

void PhfDetector::NoParseApis(EventRecordCallstack* event_record)
{
	return;
}

bool PhfDetector::isUselessApi(const string & api)
{
	if (strstr(api.c_str(), "NOOAPI") != nullptr ||
		strstr(api.c_str(), "NOMODULE") != nullptr ||
		strstr(api.c_str(), "NOAPI") != nullptr)
	{
		return true;
	}
	if (lcsdetect_api_keylogger.find(api) != lcsdetect_api_keylogger.end())
	{
		return false;
	}
	else if (lcsdetect_api_screengrab.find(api) != lcsdetect_api_screengrab.end())
	{
		return false;
	}
	else if (lcsdetect_api_processinject.find(api) != lcsdetect_api_processinject.end())
	{
		return false;
	}
	else if (remoteshell_sigs.find(api) != remoteshell_sigs.end())
	{
		return false;
	}// add by zxw on 20200619
	else if (lcsdetect_api_reflective.find(api) != lcsdetect_api_reflective.end()) {
		return false;
	}


	return true;
}

void PhfDetector::InitMLAPIFilter()
{
	string indexmapfile = "API.csv";
	ifstream infile(indexmapfile);

	if (!infile) {
		LoggerRecord::WriteLog(L"error opening input file: " + ToolFunctions::StringToWString(indexmapfile), LogLevel::ERR);
		return;
	}
	int linenum = 0;
	for (string line = ""; getline(infile, line); linenum++) {
		api2index_map[line] = linenum;
	}
	api_index_num = linenum;

	string allindexmapfile = "API-system.csv";
	ifstream allinfile(allindexmapfile);

	if (!allinfile)
	{
		LoggerRecord::WriteLog(L"error opening input file: " + ToolFunctions::StringToWString(allindexmapfile), LogLevel::ERR);
		return;
	}
	int alllinenum = 0;
	for (string line = ""; getline(allinfile, line); alllinenum++)
	{
		allapi2index_map[line] = alllinenum;
	}
	all_api_index_num = alllinenum;

	string callstackmapfile = "cs_impotance.csv";
	ifstream infile2(callstackmapfile);
	if (!infile2) {
		LoggerRecord::WriteLog(L"error opening input file: " + ToolFunctions::StringToWString(indexmapfile), LogLevel::ERR);
		return;
	}
	int linenum2 = 0;
	for (string line = ""; getline(infile2, line); linenum2++) {
		auto local = line.find_last_not_of(',');
		if (local != line.npos) {
			line = line.substr(0, local + 1);
		}
		else continue;
		vector<string> strtemp;
		StringUtil::split(line, ',', strtemp);
		vector<int> temp;
		for (string str : strtemp)
		{
			int t = FindApiIndex(str);
			if (t != -1) temp.push_back(t);
		}
		if (!temp.empty()) callstack_vec.push_back(temp);
	}
}

bool PhfDetector::isUselessCallstack(const vector<int> & callstack)
{
	if (callstack.empty())
	{
		return true;
	}
	bool flag = false;
	for (int i = 0; i < callstack_vec.size(); i++) {
		if (callstack.size() == callstack_vec[i].size())
		{
			flag = true;
			for (int j = 0; j < callstack.size(); j++) {
				if (callstack[j] != callstack_vec[i][j])
				{
					flag = false;
					break;
				}
			}
			if (flag) break;
		}
	}
	return flag;
}

int PhfDetector::FindApiIndex(string api)
{
	if (api.size() == 0 || strstr(api.c_str(), "NOOAPI") != nullptr ||
		strstr(api.c_str(), "NOMODULE") != nullptr ||
		strstr(api.c_str(), "NOAPI") != nullptr)
	{
		return -1;
	}
	if (api2index_map.find(api) == api2index_map.end()) return -1;
	return api2index_map[api];
}

int PhfDetector::FindAllApiIndex(string api)
{
	if (api.size() == 0 || strstr(api.c_str(), "NOOAPI") != nullptr ||
		strstr(api.c_str(), "NOMODULE") != nullptr ||
		strstr(api.c_str(), "NOAPI") != nullptr)
	{
		return -1;
	}
	if (allapi2index_map.find(api) == allapi2index_map.end()) return -1;
	return allapi2index_map[api];
}

bool PhfDetector::isRepetitiveCallstack(const vector<int>& api, vector<int>& precallstack)
{
	if (api.size() != precallstack.size())
	{
		return false;
	}
	for (int i = 0; i < api.size(); i++)
	{
		if (api[i] != precallstack[i]) {
			return false;
		}
	}
	return true;
}

void PhfDetector::KeyloggerEraseMap(DWORD tid)
{
	auto iter = _thread_keylogger_timestamp_map.find(tid);
	if (iter != _thread_keylogger_timestamp_map.end()) {
		_thread_keylogger_timestamp_map.erase(iter);
	}
}

bool PhfDetector::KeyloggerPruner(DWORD tid, int_64 timestamp)
{
	auto& iter = _thread_keylogger_timestamp_map.find(tid);
	if (iter == _thread_keylogger_timestamp_map.end()) {
		_thread_keylogger_timestamp_map[tid] = timestamp;
		return true;
	}
	else {
		if (timestamp - iter->second > 100)
		{
			iter->second = timestamp;
			return true;
		}
	}
	return false;
}

//EventRecord* Detector::notify_thread_end(EventRecord* event_record) {
//	EventRecord* fake_event_record = new EventRecordCallstack(event_record->get_process_id_(), event_record->get_thread_id_(), event_record->get_time_stamp_());
//	fake_event_record->set_event_identifier_(*(new EventIdentifier(32, 0xdef2fe46)));
//	PushBack(fake_event_record, true);
//	thread_to_api.erase(fake_event_record->get_thread_id_());
//	return fake_event_record;
//}

EventRecord* PhfDetector::PushBack(EventRecordCallstack* event_record)
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	const String& callstack = event_record->get_callstack_();
	if (strstr(callstack.c_str(), "NOOAPI") != nullptr ||
		strstr(callstack.c_str(), "NOMODULE") != nullptr ||
		strstr(callstack.c_str(), "NOAPI") != nullptr)
	{
		return nullptr;
	}
	if (Setting::GetInstance().enable_debug_output())
	{
		LoggerRecord::WriteLog(L"PushBack callstack " + ToolFunctions::StringToWString(callstack) +
			L" process_id " + std::to_wstring(process_id) +
			L" thread_id " + std::to_wstring(thread_id), LogLevel::DEBUG);
	}
#ifdef USE_RAW_SIGNATURE
	if (callstack == "waveInOpen" || callstack == "waveInAddBuffer")
#else
	if (audiorecord_sigs.find(callstack) != audiorecord_sigs.end())
#endif // USE_RAW_SIGNATURE;
	{
		event_record->SetLabel("AudioRecord");
		return event_record;
	}
#ifdef USE_RAW_SIGNATURE
	else if (callstack == "GdipSaveImageToStream")
#else
	else if (remotedesktop_sigs.find(callstack) != remotedesktop_sigs.end())
#endif // USE_RAW_SIGNATURE;
	{
		event_record->SetLabel("RemoteDesktop");
		return event_record;
	}
#ifdef USE_RAW_SIGNATURE
	else if (callstack.find("CreatePipe") != std::string::npos)
#else
	else if (remoteshell_sigs.find(callstack) != remoteshell_sigs.end())
#endif // USE_RAW_SIGNATURE;
	{
		create_pipe_pids.insert(event_record->get_process_id_());
	}
	else if (lcsdetect_api_keylogger.find(callstack) != lcsdetect_api_keylogger.end())
	{
		int_64 timestamp = (int_64)(event_record->get_time_stamp_() / 1000000);
		//         LoggerRecord::WriteLog(L"keylogger callstack " + ToolFunctions::StringToWString(callstack) +
		//             L" process_id " + std::to_wstring(process_id) +
		//             L" thread_id " + std::to_wstring(thread_id) +
		//              L" timestamp " + std::to_wstring(timestamp) , LogLevel::DEBUG);
		if (KeyloggerPruner(thread_id, timestamp))    // 每100ms算一次命中
		{
			//             LoggerRecord::WriteLog(L"****** keylogger callstack " + ToolFunctions::StringToWString(callstack) +
			//                 L" process_id " + std::to_wstring(process_id) +
			//                 L" thread_id " + std::to_wstring(thread_id) +
			//                  L" timestamp " + std::to_wstring(timestamp), LogLevel::DEBUG);           
			KeyloggerApiDataQueue& api_queue = _thread_keylogger_api_queue_map[thread_id];
			if (api_queue.size() >= 10)
			{
				api_queue.pop();
			}

			api_queue.emplace(process_id, thread_id, timestamp, callstack);
			if ((api_queue.size() >= 10) && (api_queue.back().timestamp - api_queue.front().timestamp <= 6000))
			{
				HWND fg_window = GetForegroundWindow();
				DWORD fg_pid;
				GetWindowThreadProcessId(fg_window, &fg_pid);
				if (fg_pid == process_id) {
					LoggerRecord::WriteLog(L"PhfDetector::TryDetectPhf: foreground Keylogger skip, pid = " + std::to_wstring(fg_pid), LogLevel::DEBUG);
				}
				else {
					//const KeyloggerApiData& api_data = api_queue.back();
					event_record->SetLabel("Keylogger");
					//keylogger_process_cache.insert(process_id);
					keylogger_thread_cache.insert(thread_id);
					LoggerRecord::WriteLog(L"PhfDetector::PushBack keylogger process_id: " + to_wstring(process_id) +
						L" thread_id: " + to_wstring(thread_id), LogLevel::DEBUG);
				}
				_thread_keylogger_api_queue_map.erase(thread_id);
				// add by zxw on 20210105
				KeyloggerEraseMap(thread_id);
			}
		}
	}
	else if (lcsdetect_api_reflective.find(callstack) != lcsdetect_api_reflective.end()) {

		int_64 timestamp = (int_64)(event_record->get_time_stamp_() / 1000000000);
		KeyloggerApiDataQueue& api_queue = _thread_reflective_api_queue_map[process_id];
		if (api_queue.size() >= 12) {
			api_queue.pop();
		}
		//         LoggerRecord::WriteLog(L"ReflectiveLoading callstack " + ToolFunctions::StringToWString(callstack)+
		//             L" process_id " + std::to_wstring(process_id)+
		//             L" thread_id " + std::to_wstring(thread_id)+
		//             L" timestamp " + std::to_wstring(timestamp)+
		//             L" size  " + std::to_wstring(api_queue.size()), LogLevel::DEBUG);
		api_queue.emplace(process_id, thread_id, timestamp, callstack);
		if ((api_queue.size() >= 12) && (api_queue.back().timestamp - api_queue.front().timestamp <= 6)) {
			int apicouts = 0;
			auto apiresult = ReflectiveApiCounts(api_queue, apicouts);
			if (apiresult && apicouts > 3)
			{
				// add by zxw on 20200811
				Filter::GetInstance().OnPhfDetectorResult(process_id);

				event_record->SetLabel("ReflectiveLoading");
				LoggerRecord::WriteLog(L"PhfDetector::PushBack ReflectiveLoading apicouts: " + to_wstring(apicouts) +
					L" process_id: " + to_wstring(process_id), LogLevel::DEBUG);
			}
			_thread_reflective_api_queue_map.erase(process_id);
		}
	}

	//过滤;
	if (isUselessApi(event_record->get_callstack_()))
	{
		return nullptr;
	}

	//CreatePipe will insert again
	if (event_record->GetLabel() == "")
	{
		if (thread_to_apis.count(thread_id) != 0)
		{
			thread_to_apis[thread_id] = thread_to_apis[thread_id] + "," + callstack;
			// add by zxw on 20191223
			if (thread_to_apis[thread_id].length() > MAX_PHF_SIZE)
			{
				_detect_phf_flag = true;
			}
		}
		else
		{
			thread_to_apis[thread_id] = callstack;
			pid_to_thread[thread_id] = std::make_pair(process_id, event_record->get_time_stamp_());
		}
		return nullptr;
	}
	else
	{
		return event_record;
	}
}


void PhfDetector::TryDetectPhf()
{
	if (!_detect_phf_flag)	return;
	_detect_phf_flag = false;

	EventRecordList detect_result;

	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);
	//StartingTime.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart == second = second * 10的7次方 = 100ns
	if (EventRecord::frequency.QuadPart != 0)
	{
		ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::start_etwtime / EventRecord::frequency.QuadPart) * 10000000.0); //100-ns 
		check_timestamp = (EventRecord::start_systemtime + intervaltime) * 100; //1 * 100ns = 100ns 
	}

	int_64 sum_size = 0;
	int_64 capacity_size = 0;
	int_64 string_size = 0;
	for (auto i = thread_to_apis.begin(); i != thread_to_apis.end(); i++)
	{
		sum_size += 4;
		sum_size += (i->second.capacity() + 28);
	}
	sum_size = sum_size / 1024;
	string temp = "PhfDetector::thread_to_apis map before clean use memory: " + std::to_string(sum_size) + "KB";
#ifdef OUTPUT_COMMAND_LINE       
	cout << temp.c_str() << endl;
#endif // OUTPUT_COMMAND_LINE;
	LoggerRecord::WriteLog(L"" + ToolFunctions::StringToWString(temp), LogLevel::INFO);

	for (auto iter = thread_to_apis.begin(); iter != thread_to_apis.end();)
	{
		// mod by zxw on 20191223 phf data length > MAX_PHF_SIZE detector it
		//if (check_timestamp - thread_to_pid[iter->first].second < NS_SIX_SECOND)
		if (check_timestamp - pid_to_thread[iter->first].second < NS_SIX_SECOND && iter->second.length() < MAX_PHF_SIZE)
		{
			iter++;
			continue;
		}

		EventRecordCallstack* fake_event_record = nullptr;

		if (detected_remoteshell.find(pid_to_thread[iter->first].first) != detected_remoteshell.end())
		{
			if (!fake_event_record)
				fake_event_record = new EventRecordCallstack(pid_to_thread[iter->first].first, iter->first, pid_to_thread[iter->first].second);
			fake_event_record->SetLabel("RemoteShell");
			detected_remoteshell.erase(pid_to_thread[iter->first].first);
			//no need break, detector support callstack have many label
		}

		vector<string> screengrab_api;
		vector<string> processinject_api;
		int keystate_count = 0;	//todo not used;
		CalculateApiDetail(iter->second, screengrab_api, processinject_api, keystate_count);

		//LoggerRecord::WriteLog(L"screengrab_api: " + std::to_wstring(screengrab_api.size()) + L" ; " + std::to_wstring(processinject_api.size()), INFO);

		if (screengrab_api.size() != 0)
		{
			for (int i = 0; i < screengrab_sigs.size(); i++)
			{
				int_32 lcs_result = lcs(screengrab_api, screengrab_sigs[i]);
				if (lcs_result >= (int_32)screengrab_sigs[i].size())
				{
					HWND fg_window = GetForegroundWindow();
					DWORD fg_pid;
					GetWindowThreadProcessId(fg_window, &fg_pid);
					auto pid = pid_to_thread[iter->first].first;
					if (fg_pid == pid)
					{
						LoggerRecord::WriteLog(L"PhfDetector::TryDetectPhf: foreground screengrab skip, pid = " + std::to_wstring(fg_pid), LogLevel::INFO);
						break;
					}
					// add by zxw on 20201229 当进程有窗口则跳过
					if (ThreadTaskManager::GetInstance().GetVisibleWindow(GET_VISIBLE_WINDOW_TASK_MODE, pid))
					{
						LoggerRecord::WriteLog(L"PhfDetector::TryDetectPhf: has visible window screengrab skip, pid = " + std::to_wstring(pid), LogLevel::INFO);
						break;
					}

					if (!fake_event_record)
					{
						fake_event_record = new EventRecordCallstack(pid, iter->first, pid_to_thread[iter->first].second);
					}
					fake_event_record->SetLabel("ScreenGrab");
					break;
				}
			}
		}

		//further detect by detect framework,link process A->B 
		if (processinject_api.size() != 0)
		{
			for (int i = 0; i < processinjection_sigs.size(); i++)
			{
				int_32 lcs_result = lcs(processinject_api, processinjection_sigs[i]);
				if (lcs_result >= (int_32)processinjection_sigs[i].size())
				{
					if (processinjection_sigs[i].size() == 2)
					{
						//whether inject process have create process
						if (!parent_process_create.count(pid_to_thread[iter->first].first))
							continue;
					}
					if (!fake_event_record)
					{
						fake_event_record = new EventRecordCallstack(pid_to_thread[iter->first].first, iter->first, pid_to_thread[iter->first].second);
					}
					fake_event_record->SetLabel("ProcessInjection");
					//event_record->set_callstack("ProcessInjection");
					break;
				}
			}
		}

		if (fake_event_record)
		{
			detect_result.push_back(fake_event_record);
		}
		thread_to_apis.erase(iter++);
	}

	for (auto iter = parent_process_end.begin(); iter != parent_process_end.end();)
	{
		if (check_timestamp - iter->second < 12000000000) {
			iter++;
			continue;
		}
		if (parent_process_create.count(iter->first))
		{
			if (parent_process_create[iter->first] < iter->second)
			{
				parent_process_create.erase(iter->first);
			}
			parent_process_end.erase(iter++);
		}
		iter++;
	}

	//clear expired keylogger api;
	int_32 expire_time = ToolFunctions::GetUnixTimestamp() - 6;
	auto iter_keylogger_api = _thread_keylogger_api_queue_map.begin();
	while (iter_keylogger_api != _thread_keylogger_api_queue_map.end())
	{
		if (iter_keylogger_api->second.size() == 0 || iter_keylogger_api->second.back().timestamp < expire_time)
		{
			iter_keylogger_api = _thread_keylogger_api_queue_map.erase(iter_keylogger_api);
			// add by zxw on 20210105
			KeyloggerEraseMap(iter_keylogger_api->first);
		}
		else
		{
			++iter_keylogger_api;
		}
	}
	//clear expired reflective api;
	auto iter_reflective_api = _thread_reflective_api_queue_map.begin();
	while (iter_reflective_api != _thread_reflective_api_queue_map.end()) {
		if (iter_reflective_api->second.size() == 0 || iter_reflective_api->second.back().timestamp < expire_time) {
			iter_reflective_api = _thread_reflective_api_queue_map.erase(iter_reflective_api);
		}
		else {
			++iter_reflective_api;
		}
	}

	for (auto& rec : detect_result)
	{
		//InitCollector::GetCollector()->PushSendRecord(rec);
		// add by zxw on 20191107 添加空指针保护
		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(rec);
		else
		{
			EventRecordManager::GetInstance().RecycleEventRecord(rec);
			LoggerRecord::WriteLog(L"TryDetectPhf InitCollector::GetCollector is null ", LogLevel::ERR);
		}
	}
}
