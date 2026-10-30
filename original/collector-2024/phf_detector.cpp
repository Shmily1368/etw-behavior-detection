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

using namespace std;

static std::unordered_map<DWORD, vector<int> > process_to_precallstack;
static std::unordered_map<DWORD, string> thread_to_apis;
static std::unordered_map<DWORD, std::pair<DWORD, ULONG64>> pid_to_thread;
static std::unordered_map<DWORD, std::pair<DWORD, ULONG64>> thread_to_pid;
static std::unordered_set<int> create_pipe_pids;
static std::unordered_set<int> detected_remoteshell;
static std::unordered_set<string> lcsdetect_api_screengrab;
static std::unordered_set<string> lcsdetect_api_processinject;
static std::unordered_set<string> lcsdetect_api_keylogger;
static std::unordered_set<string> lcsdetect_api_reflective;

static ULONG64 check_timestamp;
static std::unordered_map<DWORD, ULONG64> parent_process_create;
static std::unordered_map<DWORD, ULONG64> parent_process_end;
KeyloggerProcessSet PhfDetector::m_setKeyloggerThreadCache;
static std::unordered_map<string, int> api2index_map;
static std::vector<std::vector<int> > callstack_vec;
static std::unordered_map<DWORD, vector<int> > process_to_apis_modern;
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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open keylogger_signature failed, code = %d", GetLastError());

	//screengrab;
	//fp.open(phf_signature_folder + "screengrab_signature", ios::in | ios::binary);

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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open screengrab_signature failed, code = %d", GetLastError());


	//processinjection;
	//fp.open(phf_signature_folder + "processinjection_signature", ios::in | ios::binary);

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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open screengrab_signature failed, code = %d", GetLastError());


	//audiorecord;
	//fp.open(phf_signature_folder + "audiorecord_signature", ios::in | ios::binary);

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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open audiorecord_signature failed, code = %d", GetLastError());


	//remotedesktop;
	//fp.open(phf_signature_folder + "remotedesktop_signature", ios::in | ios::binary);

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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open remotedesktop_signature failed, code = %d", GetLastError());


	//remoteshell;
	//fp.open(phf_signature_folder + "remoteshell_signature", ios::in | ios::binary);

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
	}else
		WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open remoteshell_signature failed, code = %d", GetLastError());

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
        WriteLog4cPlus(ERROR_LEVEL, L"PhfDetector::Init open keylogger_signature failed, code = %d", GetLastError());

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
    int reflectice_api[5] = {0};
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

    for (int i = 0; i< 5; i++)
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
    m_setKeyloggerThreadCache.erase(ttid);
}

void PhfDetector::OutputDetectPhf()
{
	if (!m_bDetectPhfFlag)	return;
	
	m_bDetectPhfFlag = false;
	
	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);

	if (EventRecord::m_liFrequency.QuadPart != 0)
	{
		ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::m_ulStartEtwtime / EventRecord::m_liFrequency.QuadPart) * 10000000.0); //100-ns 
		check_timestamp = (EventRecord::m_nStartSystemtime + intervaltime) * 100; //1 * 100ns = 100ns 
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
		using namespace std::chrono;
		// 获取当前时间
		auto now = system_clock::now();
		// 获取时间戳（单位：微秒）
		auto timestamp1 = time_point_cast<microseconds>(now).time_since_epoch().count();
		// 将时间戳转换为毫秒
		long long timestamp_milliseconds = timestamp1 / 1000.0;
		//EventRecordCallstack* ev_phf = new EventRecordCallstack(pid, tid, timestamp);
		EventRecordCallstack* ev_phf = new EventRecordCallstack(pid, tid, timestamp_milliseconds);
		ev_phf->SetLabel(s);
		//ev_phf->QPCtimeToSystime();
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

void PhfDetector::ParseThread2ApisFullWithVec(EventRecordCallstack* event_record)//real use
{
	DWORD process_id = event_record->get_process_id_();
	DWORD thread_id = event_record->get_thread_id_();
	const vector<int>& callstack = event_record->get_vec_callstack_();
	if (callstack.empty())
	{
		return;
	}
	if (process_to_precallstack.count(process_id) == 0)
	{
		 process_to_precallstack[process_id] = vector<int>{};
	}

	if (process_to_apigroups.count(process_id) == 0)
	{
		process_to_apigroups[process_id] = set<int>{};
	}
	
	vector<int> precallstack = process_to_precallstack[process_id];
	if (isRepetitiveCallstack(callstack, precallstack))
	{
		return;
	}
	
	if (process_to_apis_modern.count(process_id) != 0)
	{
		for (int api : callstack)
			process_to_apis_modern[process_id][api]++;
	}
	else
	{
		vector<int> process_callstack(api_index_num, 0);
		for (int api : callstack)
		{
			process_callstack[api]++;
		}
		process_to_apis_modern[process_id] = process_callstack;
		pid_to_thread[process_id] = std::make_pair(thread_id, event_record->get_time_stamp_());
	}
	precallstack.clear();
	for (int api : callstack)  precallstack.push_back(api);
	process_to_precallstack[process_id] = precallstack;
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
		WriteLog4cPlus(ERROR_LEVEL, L"error opening input file: API.csv");
		return;
	}
	int linenum = 0;
	for (string line = ""; getline(infile, line); linenum++) {
		api2index_map[line] = linenum;
	}
	api_index_num = linenum;

	string callstackmapfile = "useless_cs.csv";
	ifstream infile2(callstackmapfile);
	if (!infile2) {
		WriteLog4cPlus(ERROR_LEVEL, L"error opening input file: cs_impotance.csv");
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
			string temp2 = str.substr(str.find_last_of('\\') + 1);
			int t = FindApiIndex(temp2);
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
    auto iter = m_umapTid2Timestamp.find(tid);
    if (iter != m_umapTid2Timestamp.end()) {
        m_umapTid2Timestamp.erase(iter);
    }
}

bool PhfDetector::KeyloggerPruner(DWORD tid, int_64 timestamp) 
{
    auto& iter = m_umapTid2Timestamp.find(tid);
    if (iter == m_umapTid2Timestamp.end()) {
        m_umapTid2Timestamp[tid] = timestamp;
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
        WriteLog4cPlusA(DEBUG_LEVEL, "PushBack callstack %s process_id %d thread_id %d", callstack, process_id, thread_id);
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
//         WriteLog4cPlus(L"keylogger callstack " + ToolFunctions::StringToWString(callstack) +
//             L" process_id " + std::to_wstring(process_id) +
//             L" thread_id " + std::to_wstring(thread_id) +
//              L" timestamp " + std::to_wstring(timestamp) , DEBUG_LEVEL);
        if (KeyloggerPruner(thread_id, timestamp))    
        {
//             WriteLog4cPlus(L"****** keylogger callstack " + ToolFunctions::StringToWString(callstack) +
//                 L" process_id " + std::to_wstring(process_id) +
//                 L" thread_id " + std::to_wstring(thread_id) +
//                  L" timestamp " + std::to_wstring(timestamp), DEBUG_LEVEL);           
		    KeyloggerApiDataQueue& api_queue = m_mapPid2KeyLoggerApiQueue[thread_id];
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
                    WriteLog4cPlus(DEBUG_LEVEL, L"PhfDetector::TryDetectPhf: foreground Keylogger skip, pid = %d", fg_pid);
                }
                else {
                    //const KeyloggerApiData& api_data = api_queue.back();
                    event_record->SetLabel("Keylogger");               
                    //keylogger_process_cache.insert(process_id);
                    m_setKeyloggerThreadCache.insert(thread_id);
                    WriteLog4cPlus(DEBUG_LEVEL, L"PhfDetector::PushBack keylogger process_id: %d thread_id: %d", process_id, thread_id);
                }
                m_mapPid2KeyLoggerApiQueue.erase(thread_id);
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
//         WriteLog4cPlus(L"ReflectiveLoading callstack " + ToolFunctions::StringToWString(callstack)+
//             L" process_id " + std::to_wstring(process_id)+
//             L" thread_id " + std::to_wstring(thread_id)+
//             L" timestamp " + std::to_wstring(timestamp)+
//             L" size  " + std::to_wstring(api_queue.size()), DEBUG_LEVEL);
        api_queue.emplace(process_id, thread_id, timestamp, callstack);
        if ((api_queue.size() >= 12) && (api_queue.back().timestamp - api_queue.front().timestamp <= 6)) {
            int apicouts = 0;
            auto apiresult = ReflectiveApiCounts(api_queue, apicouts);
            if (apiresult && apicouts > 3)
            {
                // add by zxw on 20200811
                Filter::GetInstance().OnPhfDetectorResult(process_id);

                event_record->SetLabel("ReflectiveLoading");                 
                WriteLog4cPlus(DEBUG_LEVEL, L"PhfDetector::PushBack ReflectiveLoading apicouts: %d process_id: %d", apicouts, process_id);
            }
             _thread_reflective_api_queue_map.erase(process_id);
        }
    }


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
                m_bDetectPhfFlag = true;
            }
		}
		else 
		{
			thread_to_apis[thread_id] = callstack;
			thread_to_pid[thread_id] = std::make_pair(process_id, event_record->get_time_stamp_());
		}
		return nullptr;
	}
	else
	{
		return event_record;
	}
}

void PhfDetector::ProcessSystemCall(EventRecordPerfInfo* ev)
{
	EventRecordList ev_phf_list;

	DWORD process_id = ev->get_process_id_();
	DWORD thread_id = ev->get_thread_id_();
	ULONG64 timestamp = ev->get_time_stamp_();
	String api_name = ToolFunctions::WStringToString(ev->GetStringParameter(parameter_index_enum::SystemCall));
#ifdef USE_RAW_SIGNATURE
	if (api_name.find("NtCreateNamedPipeFile") != std::string::npos)
#else
	if (remoteshell_sigs.find(api_name) != remoteshell_sigs.end())
#endif // USE_RAW_SIGNATURE;
	{
		create_pipe_pids.insert(process_id);
	}
	else if (lcsdetect_api_keylogger.find(api_name) != lcsdetect_api_keylogger.end())
	{
        int_64 timestamp = (int_64)(ev->get_time_stamp_() / 1000000000);
		KeyloggerApiDataQueue& api_queue = m_mapPid2KeyLoggerApiQueue[thread_id];
		if (api_queue.size() >= 20)
		{
			api_queue.pop();
		}

		api_queue.emplace(process_id, thread_id, timestamp, api_name);
		if ((api_queue.size() >= 20) && (api_queue.back().timestamp - api_queue.front().timestamp <= 6))
		{
			const KeyloggerApiData& api_data = api_queue.back();
			EventRecordCallstack* ev_phf = new EventRecordCallstack(process_id, thread_id, ev->get_time_stamp_());
			ev_phf->SetLabel("Keylogger");
			ev_phf_list.push_back(ev_phf);
			m_mapPid2KeyLoggerApiQueue.erase(thread_id);           
			//keylogger_process_cache.insert(process_id);
            m_setKeyloggerThreadCache.insert(thread_id);
            
		}
	}

	//CreatePipe will insert again
	if (ev_phf_list.empty())
	{
		if (!isUselessApi(api_name))
		{
			if (thread_to_apis.find(thread_id) != thread_to_apis.end())			
			{
				thread_to_apis[thread_id] = thread_to_apis[thread_id] + "," + api_name;
			}
			else
			{
				thread_to_apis[thread_id] = api_name;
				thread_to_pid[thread_id] = std::make_pair(process_id, ev->get_time_stamp_());
			}
		}
	}
	else
	{
		for (auto ev : ev_phf_list)
		{
			//InitCollector::GetCollector()->PushSendRecord(ev);

			if (InitCollector::GetCollector())
				InitCollector::GetCollector()->PushSendRecord(ev);
			else
			{
				EventRecordManager::GetInstance().RecycleEventRecord(ev);
				WriteLog4cPlus(ERROR_LEVEL, L"ProcessSystemCall InitCollector::GetCollector is null ");
			}
		}
	}
}

void PhfDetector::TryDetectPhf()
{
	if (!m_bDetectPhfFlag)	return;
	m_bDetectPhfFlag = false;

	EventRecordList detect_result;

	LARGE_INTEGER start_time;
	QueryPerformanceCounter(&start_time);
	
    if (EventRecord::m_liFrequency.QuadPart != 0) 
    {
        ULONG64 intervaltime = (ULONG64)((start_time.QuadPart - EventRecord::m_ulStartEtwtime / EventRecord::m_liFrequency.QuadPart) * 10000000.0); //100-ns 
        check_timestamp = (EventRecord::m_nStartSystemtime + intervaltime) * 100; //1 * 100ns = 100ns 
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
	WriteLog4cPlusA(INFO_LEVEL, temp.c_str());

	for (auto iter = thread_to_apis.begin(); iter != thread_to_apis.end();)
    {       
        // mod by zxw on 20191223 phf data length > MAX_PHF_SIZE detector it
		//if (check_timestamp - thread_to_pid[iter->first].second < NS_SIX_SECOND)
        if (check_timestamp - thread_to_pid[iter->first].second < NS_SIX_SECOND && iter->second.length() < MAX_PHF_SIZE)
		{
			iter++;
			continue;
		}

		EventRecordCallstack* fake_event_record = nullptr;

		if (detected_remoteshell.find(thread_to_pid[iter->first].first) != detected_remoteshell.end())		
		{
			if (!fake_event_record)
				fake_event_record = new EventRecordCallstack(thread_to_pid[iter->first].first, iter->first, thread_to_pid[iter->first].second);
			fake_event_record->SetLabel("RemoteShell");
			detected_remoteshell.erase(thread_to_pid[iter->first].first);
			//no need break, detector support callstack have many label
		}

		vector<string> screengrab_api;
		vector<string> processinject_api;
		int keystate_count = 0;	//todo not used;
		CalculateApiDetail(iter->second, screengrab_api, processinject_api, keystate_count);

		//WriteLog4cPlus(INFO, L"screengrab_api: " + std::to_wstring(screengrab_api.size()) + L" ; " + std::to_wstring(processinject_api.size()));

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
                    auto pid = thread_to_pid[iter->first].first;
					if (fg_pid == pid)
					{
						WriteLog4cPlus(INFO_LEVEL, L"PhfDetector::TryDetectPhf: foreground screengrab skip, pid =  %d", fg_pid);
						break;
					}

                    if (ThreadTaskManager::GetInstance().GetVisibleWindow(GET_VISIBLE_WINDOW_TASK_MODE, pid))
                    {
                        WriteLog4cPlus(INFO_LEVEL, L"PhfDetector::TryDetectPhf: has visible window screengrab skip, pid =  %d", pid);
                        break;
                    }

					if (!fake_event_record)
					{
						fake_event_record = new EventRecordCallstack(pid, iter->first, thread_to_pid[iter->first].second);
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
						if (!parent_process_create.count(thread_to_pid[iter->first].first))
							continue;
					}
					if (!fake_event_record)
					{
						fake_event_record = new EventRecordCallstack(thread_to_pid[iter->first].first, iter->first, thread_to_pid[iter->first].second);
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
	auto iter_keylogger_api = m_mapPid2KeyLoggerApiQueue.begin();
	while (iter_keylogger_api != m_mapPid2KeyLoggerApiQueue.end())
	{
		if (iter_keylogger_api->second.size() == 0 || iter_keylogger_api->second.back().timestamp < expire_time)
		{
			iter_keylogger_api = m_mapPid2KeyLoggerApiQueue.erase(iter_keylogger_api);
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

		if (InitCollector::GetCollector())
			InitCollector::GetCollector()->PushSendRecord(rec);
		else
		{
			EventRecordManager::GetInstance().RecycleEventRecord(rec);
			WriteLog4cPlus(ERROR_LEVEL, L"TryDetectPhf InitCollector::GetCollector is null ");
		}
	}
}
