#pragma once
#include <iostream>
//#include "CJsonObject.hpp"
#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <set>
//#include "event_record_callstack.h"
using namespace std;

extern const int g_nRansomapi_maxsize;
extern const int mapsize;

class feature {
private:
	int32 pid = -1;
	string process_name = "";
	int32 ppid = -1;
	string pprocess_name = "";

	int32 write_c = 0;
	int32 delete_c = 0;
	int32 dir_enum_c = 0;
	int32 read_c = 0;
	int32 rename_c = 0;
	int32 overwrite_c = 0;

	int32 file_magic_number_change = 0;
	double file_magic_number_change_v = 0;
	int32 file_similarity = 0;
	double file_similarity_v = 0;

	
	unordered_map<string, int32> file_type_r_table;
	unordered_map<string, int32> file_type_w_table;
	int32 file_type_r_c = 0;
	int32 file_type_w_c = 0;

	string action_interpretation;
	vector<string> action_path_interpretation;
	int32 irp2 = 0;
	int32 irp3 = 0;
	
	unordered_map<string, unordered_set<string>> path_hash_table;

	//int64 starting_time = 0;
	//int64 last_current_time = 0;
	//int64 current_time = 0;
	//double time_gap = 0;

	//not used
	//int32 path_c = 0;
	int32 file_c = 0;

	

	// registry
	int32 regcreate_c = 0;
	int32 regdelete_c = 0;
	int32 regquery_c = 0;
	int32 regset_c = 0;

	// dll
	vector<int32> encryptdll_c = vector<int>(mapsize,0);
	vector<int32> apis_c = vector<int>(g_nRansomapi_maxsize,0);

	/*
	double entropy_sum = 0;
	double entropy_write_read = 0;

	double r_speed = 0;
	double w_speed = 0;
	double d_speed = 0;
	double o_speed = 0;
	double n_speed = 0;
	double m_speed = 0;

	double read_frac = 0;
	double write_frac = 0;
	double delete_frac = 0;
	double rename_frac = 0;
	*/

	double file_size_change0 = 0;
	double file_size_change1 = 0;
	double file_size_change = 0;
	
	enum TUPLE_FILEOPERATION_ENUM
	{
		TFO_WRITE = 0,
		TFO_DELETE = 1,
		TFO_READ,
		TFO_OVERWRITE,
		TFO_RENAME,
	};
	/*{enum {write,delete,read,overwrite,rename}}*/
	std::map<int, std::tuple<int, int, int, int, int>> m_mapFileEnum2OperationCount 
		= { {0,{0,0,0,0,0}},{1,{0,0,0,0,0}},{2,{0,0,0,0,0}} };
	std::vector<std::tuple<int, int, int, int>> m_mapRegEnum2OperationCount
		= { {}, {}, {}, {}, {} };

	std::set<std::string> m_setWriteFilePathList;
	double dEntropy = 0;
public:
	feature()=default;
	feature(int32 Pid, string processname);
	string toString();
	void toFloats(float* pOut);
	//void update_timestamp(punit unit);
	void update_file_type(std::shared_ptr<unit> pUnit);
	void update_action_path_i(std::shared_ptr<unit> pUnit);
	void cal_access_frequency(std::shared_ptr<unit> pUnit);
	//void cal_fraction();
	void update_file_size_change(std::shared_ptr<unit> pUnit);
	//void cal_system_call(std::shared_ptr<unit> pUnit);
	void update_file_magic_number_change(std::shared_ptr<unit> pUnit);
	void update_file_similarity(std::shared_ptr<unit> pUnit);
	void cal_irp_sequence();
#ifdef ETW_USE_ENTROPY
	void CalcEntropy();
#endif // ETW_USE_ENTROPY


	void update_api();

	void update_registry();

	void update_dll();

#ifdef ETW_FEATURE_RECORD_TEST	
	void Record2Csv(std::function<VOID(stringstream&)>pFun)
	{
		bool bAdd = true;
		stringstream ss;
		string output;
		pFun(ss);
		ss << pid << ",";
		ss << process_name << ",";
		ss << ppid << ",";
		ss << pprocess_name << ",";
		ss << write_c << ",";
		ss << delete_c << ",";
		ss << dir_enum_c << ",";
		ss << read_c << ",";
		ss << rename_c << ",";
		ss << overwrite_c << ",";
		ss << file_magic_number_change << ",";
		ss << file_magic_number_change_v << ",";
		ss << file_similarity << ",";
		ss << file_similarity_v << ",";
		for (auto i : file_type_r_table)
			ss << i.first << "!" << i.second << ";";
		ss << ",";

		for (auto i : file_type_w_table)
			ss << i.first << "!" << i.second << ";";
		ss << ",";

		ss << file_type_r_c << ",";
		ss << file_type_w_c << ",";
		ss << action_interpretation << ",";
		for (auto i : action_path_interpretation)
			ss << i << ";";
		ss << ",";

		ss << irp2 << ",";
		ss << irp3 << ",";
		for (auto i : path_hash_table)
		{
			ss << i.first << "|";
			for (auto ii :i.second)
				ss << ii << "!";
			ss << ";";
		}
		ss << ",";

		//not used
		//ss << path_c << ",";
		ss << file_c << ",";
		ss << regcreate_c << ",";
		ss << regdelete_c << ",";
		ss << regquery_c << ",";
		ss << regset_c << ",";
		for (auto i : encryptdll_c)
			ss << i << ";";
		ss << ",";

		for (auto i : apis_c)
			ss << i << ";";
		ss << ",";

		ss << file_size_change0 << ",";
		ss << file_size_change1 << ",";
		ss << file_size_change << ",";
		ss << toString() << ",";
		output = ss.str();
		if (bAdd)
			g_thCRC.AddLine("feature", output.c_str());
	}
#endif

public:
	static void makeFeature(std::shared_ptr<process> Process, feature& Feature);

	static void collectFeature(feature& Feature);

	static void testFeature(feature& Feature);

	static void getUnits();

	static void feature::InsertTimeStamp(std::string strTimeStamp);
};

typedef feature* pfeature;