#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <unordered_map>

//#include "CJsonObject.hpp"


using namespace std;

#define READ 0x00000001
#define FDELETE 0x00000002
#define WRITE 0x00000004
#define RENAME 0x00000008
#define DIR_ENUM 0x00000010
#define UNKNOWN 0x0000100
#define NORMAL 0x00000200

class unit {
private:
	static unordered_map<string, int>event_dict;
public:
	int32 m_nPid = -1;
	int64 m_nCreatedTime = -1;
	//string identifier = "";
	int32 m_nReadBytes = 0;
	int32 m_nWriteBytes = 0;
	string m_strProcessName = "";
	string m_strAction = "";
	//not used
	//vector<string> apis;
	//m_vctFilepath无意义，仅初始化时候传入了filepath，弃用替换为m_strFilePath
	//vector<string> m_vctFilepath;
	std::string m_strFilePath;
	//not used
	int32 file_c = 0;
	//int32 path_c = 0;
	//int32 dir_c = 0;
	vector<int32> m_vctFileSimilarity;
	int32 m_nFileMagicNumberChange = 0;
	vector<vector<int32>> m_vctFileSize;
	//double id = -1;
	//vector<string> type_c;
	//int isFinish;
	vector<string> m_vctEventsName;
	
	unit() = default;

	unit(int32 Pid, int64 timestamp, string processname, string filePath) {
		m_nPid = Pid;
		m_nCreatedTime = timestamp;
		m_strProcessName = processname;
		m_strFilePath = filePath;
	}

	void eventToInt(vector<int32> &eventint) {
		
		for (int i = 0; i < m_vctEventsName.size(); i++)
		{
			if (event_dict.find(m_vctEventsName[i]) != event_dict.end()) {
				eventint.push_back(event_dict[m_vctEventsName[i]]);
			}
		}
		
	}

	void setAction(vector<int32> &eventint) {                                     //make the action after the unit is finish.
		int action_id = 0;
		if (eventint.size() >= 2 && eventint[0] == 0 && eventint[eventint.size() - 1] == 6) {
			if (find(eventint.begin(), eventint.end(), 1) != eventint.end()) {
				action_id |= READ;
			}
			if (find(eventint.begin(), eventint.end(), 2) != eventint.end()) {
				action_id |= WRITE;
			}
			if (find(eventint.begin(), eventint.end(), 3) != eventint.end()) {
				action_id |= FDELETE;
			}
			else if (find(eventint.begin(), eventint.end(), 4) != eventint.end()) {
				action_id |= RENAME;
			}
			else if (find(eventint.begin(), eventint.end(), 5) != eventint.end()) {
				action_id |= DIR_ENUM;
			}
			else {
				action_id |= NORMAL;
			}
		}
		else {
			action_id |= UNKNOWN;
		}
		if ((action_id & READ) && (action_id & WRITE)) {
			//if (&*find(eventint.rbegin(), eventint.rend(), 2) - &*find(eventint.begin(), eventint.end(), 1) > 0) {
			//	action = "overwrite";
			//}
			//else {
			//	action = "write";
			//}
			m_strAction = "overwrite";
		}
		else if ((action_id & READ) && !(action_id & WRITE)) {
			m_strAction = "read";
		}
		else if ((action_id & WRITE) && !(action_id & READ)) {
			m_strAction = "write";
		}
		else if (action_id & RENAME) {
			m_strAction = "rename";
		}
		else if (action_id & FDELETE) {
			m_strAction = "delete";
		}
		else if (action_id & DIR_ENUM) {
			m_strAction = "dir_enum";
		}
		else if (action_id & NORMAL) {
			m_strAction = "normal";
		}
		else {
			m_strAction = "unknown";
		}
	}

#ifdef ETW_UNIT_RECORD_TEST	
	void Record2Csv(std::function<VOID (stringstream& )>pFun)
	{
		bool bAdd = true;
		stringstream ss;
		string output;
		pFun(ss);
		ss << m_nPid << ",";
		ss << m_nReadBytes << ",";
		ss << m_nWriteBytes << ",";
		ss << m_strProcessName << ",";
		ss << m_strAction << ",";
		ss << m_nFileMagicNumberChange << ",";
		ss << m_strFilePath << ",";

		for (auto i : m_vctFileSimilarity)
			ss << i << ";";
		ss << ",";

		for (auto i : m_vctFileSize)
		{
			for (auto ii : i)
				ss << ii << "!";
			ss <<";";
		}
		ss << ",";

		for (auto i : m_vctEventsName)
			ss << i << ";";

		output = ss.str();
		if (bAdd)
			g_thCRC.AddLine("unit", output.c_str());
	}
#endif
};
typedef unit* punit;

