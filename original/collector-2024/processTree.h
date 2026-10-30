#pragma once
#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

typedef class process {
public:
	int pid = -1;
	string path = "";
	int64 startTime = -1;
	bool isalive = false;
	string parentName;
	int parentPid = -1;
	std::shared_ptr<process>parent = nullptr;          //parent process
	vector<std::shared_ptr<process>> son;           //son process

	//vector<string> apis;             //apis which process executes
	vector<std::shared_ptr<unit>> m_vctUnits;             //units which process executes
	//unordered_map<string, unit> m_umapFileObject2EventUnits;
	unordered_map<string,std::shared_ptr<unit>> m_umapFileObject2EventUnits;
	//vector<string> tempApis;   // process the api in consistent way

	process() {
		isalive = true;
	}
	process(int Pid) {
		pid = Pid;
		isalive = true;
	}
	process(int Pid, string Path, int64 StartTime) {
		pid = Pid;
		path = Path;
		startTime = StartTime;
		isalive = true;
	}
	void setParent(std::shared_ptr<process> Parent) {
		parent = Parent;
	}
	void addSon(std::shared_ptr<process> Son) {
		son.push_back(Son);
	}

#ifdef ETW_FEATURE_RECORD_TEST	
	VOID Record2csv(stringstream& ss)
	{
		ss << pid << ",";
		ss << path << ",";
		ss << startTime << ",";
		ss << isalive << ",";
		ss << parentPid << ",";
		ss << parentName << ",";
		
	}

	void Record2Csv(std::function<VOID(stringstream&)>pFun)
	{
		bool bAdd = true;
		stringstream ss;
		string output;
		pFun(ss);
		Record2csv(ss);
		output = ss.str();
		if (bAdd)
			g_thCRC.AddLine("process", output.c_str());
	}
#endif
}process, *pprocess;
