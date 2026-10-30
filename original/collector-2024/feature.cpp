#include "stdafx.h"
#include "unit.h"
#include "event.h"
#include "processTree.h"
#include "feature.h"
#include <unordered_map>
#include <fstream>
#include "event_record.h"
#include "event_record_manager.h"
#include "tool_functions.h"
#include "init_collector.h"
#include "setting.h"
#include "filter.h"
#include "tool_functions.h"
#include "RegistryUnit.h"
#include "DllUnit.h"
#include "CallstackUnit.h"
#include "FilterRule.h"
#include "process_event_info.h"
#include <unordered_map>
#include "RansomCheck.h"

std::unordered_map<std::string, int> g_umapRemoveDuplicatesFeature;

//extern std::mutex g_mutexVctProcessUnitTree;
extern vector<std::shared_ptr<process>> g_vctProcessUnitTree;
//extern const STRING_VECTOR ransomapi_need_vec;
extern const int testwindow;

string scale_by_range(const string& input);
int predict(const string& test);
//string range_path = "data\\features.all-etw.range";
//string model_path = "data\\features.all-etw.model";
string range_path_overwrite = "data\\features.all-etw-overwrite.range";
string model_path_overwrite = "data\\features.all-etw-overwrite.model";
string range_path_irp2 = "data\\features.all-etw-irp2.range";
string model_path_irp2 = "data\\features.all-etw-irp2.model";
string range_path_irp3 = "data\\features.all-etw-irp3.range";
string model_path_irp3 = "data\\features.all-etw-irp3.model";
const string output_path = "output\\output.out";
const string all_path = "output\\allfeature.out";
const string train_path = "train\\trainfeature.out";
std::mutex g_mutexAllPath;


feature::feature(int32 Pid, string processname) {
	pid = Pid;
	process_name = processname;
}

string feature::toString(void) {                          //print the format which svm needs.
	stringstream ss;
	string output;
	ss << "0";

	//ss << " 1:" << api1;    // CryptImportKey","CryptDecrypt 二分
	//ss << " 2:" << api3;    // K32GetProcessImageFileName

	ss << " 1:" << testwindow;

	ss << " 2:" << file_c;
	ss << " 3:" << delete_c;
	ss << " 4:" << write_c;
	ss << " 5:" << dir_enum_c;
	ss << " 6:" << read_c;
	ss << " 7:" << rename_c;
	ss << " 8:" << overwrite_c;

	ss << " 9:" << file_type_w_c;
	ss << " 10:" << file_type_r_c;

	ss << " 11:" << file_size_change0;
	ss << " 12:" << setiosflags(ios::fixed) << setprecision(2) << file_size_change;    
	ss << " 13:" << setiosflags(ios::fixed) << setprecision(2) << file_magic_number_change_v;  //double(delete_c) / double(file_c);
	ss << " 14:" << setiosflags(ios::fixed) << setprecision(2) << file_similarity_v;

	ss << " 15:" << irp2;
	ss << " 16:" << irp3;

	int count = 17;

	for(auto dll : encryptdll_c)
	{
		ss << " " << count << ":" << dll;
		count++;
	}

	for (auto api : apis_c)
	{
		ss << " " << count << ":" << api;
		count++;
	}
	ss << " " << count << ":" << regcreate_c; count++;
	ss << " " << count << ":" << regdelete_c; count++;
	ss << " " << count << ":" << regquery_c;  count++;
	ss << " " << count << ":" << regset_c;    count++;

	for (auto i: m_mapRegEnum2OperationCount)
	{
		int nCreate = 0;
		int nDelete = 0;
		int nQuery = 0;
		int nSet = 0;
		std::tie(nCreate, nDelete, nQuery, nSet) = i;
		ss << " " << count << ":" << nCreate;
		count++;
		ss << " " << count << ":" << nDelete;
		count++;
		ss << " " << count << ":" << nQuery;
		count++;
		ss << " " << count << ":" << nSet;
		count++;
	}

	for (auto i : m_mapFileEnum2OperationCount)
	{
		int nWrite = 0;
		int nDelete = 0;
		int nRead = 0;
		int nOverwrite = 0;
		int nRename = 0;
		std::tie(nWrite, nDelete, nRead, nOverwrite, nRename) = i.second;
		ss << " " << count << ":" << nWrite;
		count++;
		ss << " " << count << ":" << nDelete;
		count++;
		ss << " " << count << ":" << nRead;
		count++;
		ss << " " << count << ":" << nOverwrite;
		count++;
		ss << " " << count << ":" << nRename;
		count++;
	}
	ss << " " << count << ":" << dEntropy;

	output = ss.str();
	return output;
}

void feature::toFloats(float* pOut) {                          //print the format which rf needs.
	int nIndex = 0;
	pOut[nIndex] = testwindow;
	nIndex++;
	pOut[nIndex] = file_c;
	nIndex++;
	pOut[nIndex] = delete_c;
	nIndex++;
	pOut[nIndex] = write_c;
	nIndex++;
	pOut[nIndex] = dir_enum_c;
	nIndex++;
	pOut[nIndex] = read_c;
	nIndex++;
	pOut[nIndex] = rename_c;
	nIndex++;
	pOut[nIndex] = overwrite_c;
	nIndex++;
	pOut[nIndex] = file_type_w_c;
	nIndex++;
	pOut[nIndex] = file_type_r_c;
	nIndex++;

	pOut[nIndex] = file_size_change0;
	nIndex++;
	pOut[nIndex] = file_size_change;
	nIndex++;
	pOut[nIndex] = file_magic_number_change_v;
	nIndex++;
	pOut[nIndex] = file_similarity_v;
	nIndex++;

	pOut[nIndex] = irp2;
	nIndex++;
	pOut[nIndex] = irp3;
	nIndex++;

	for (auto dll : encryptdll_c)
	{
		pOut[nIndex] = dll;
		nIndex++;
	}

	for (auto api : apis_c)
	{
		pOut[nIndex] = api;
		nIndex++;
	}

	pOut[nIndex] = regcreate_c;
	nIndex++;
	pOut[nIndex] = regdelete_c;
	nIndex++;
	pOut[nIndex] = regquery_c;
	nIndex++;
	pOut[nIndex] = regset_c;
	nIndex++;

	for (auto i : m_mapRegEnum2OperationCount)
	{
		int nCreate = 0;
		int nDelete = 0;
		int nQuery = 0;
		int nSet = 0;
		std::tie(nCreate, nDelete, nQuery, nSet) = i;
		pOut[nIndex] = nCreate;
		nIndex++;
		pOut[nIndex] = nDelete;
		nIndex++;
		pOut[nIndex] = nQuery;
		nIndex++;
		pOut[nIndex] = nSet;
		nIndex++;
	}

	for (auto i : m_mapFileEnum2OperationCount)
	{
		int nWrite = 0;
		int nDelete = 0;
		int nRead = 0;
		int nOverwrite = 0;
		int nRename = 0;
		std::tie(nWrite, nDelete, nRead, nOverwrite, nRename) = i.second;
		pOut[nIndex] = nWrite;
		nIndex++;
		pOut[nIndex] = nDelete;
		nIndex++;
		pOut[nIndex] = nRead;
		nIndex++;
		pOut[nIndex] = nOverwrite;
		nIndex++;
		pOut[nIndex] = nRename;
		nIndex++;
	}
}

/*
void feature::update_timestamp(punit unit) {             //update the feature timestamp
	current_time = unit->created_time / (int64)1000000;
	if (starting_time == 0) {
		starting_time = current_time;
		last_current_time = current_time;
	}
}
*/

void feature::update_file_type(std::shared_ptr<unit> pUnit) {             //process file type change feature.
	if (pUnit->m_strFilePath.empty())
		return;
	string path = pUnit->m_strFilePath;
	if (path.rfind('.') == -1) {
		return;
	}
	else {
		path = path.substr(path.rfind('.') + 1);
		if (pUnit->m_strAction == "write"
			|| pUnit->m_strAction == "overwrite") {
			if (file_type_w_table.find(path) == file_type_w_table.end()) {
				file_type_w_table.insert(pair<string, int32>{ path, 1 });
				file_type_w_c += 1;
			}
			else {
				file_type_w_table[path] += 1;
			}
		}
		if (pUnit->m_strAction == "read" 
			|| pUnit->m_strAction == "overwrite") {
			if (file_type_r_table.find(path) == file_type_r_table.end()) {
				file_type_r_table.insert(pair<string, int32>{ path, 1 });
				file_type_r_c += 1;
			}
			else {
				file_type_r_table[path] += 1;
			}
		}
	}
}

void feature::update_action_path_i(std::shared_ptr<unit> pUnit) {            //record the unit actions.
	if (pUnit->m_strAction == "write") {
		action_path_interpretation.push_back(pUnit->m_strFilePath);
		action_interpretation += "w";
	}
	else if (pUnit->m_strAction == "delete") {
		action_path_interpretation.push_back(pUnit->m_strFilePath);
		action_interpretation += "d";
	}
	else if (pUnit->m_strAction == "read") {
		action_path_interpretation.push_back(pUnit->m_strFilePath);
		action_interpretation += "r";
	}
	else if (pUnit->m_strAction == "overwrite") {
		action_path_interpretation.push_back(pUnit->m_strFilePath);
		action_interpretation += "o";
	}
	else if (pUnit->m_strAction == "rename") {
		action_path_interpretation.push_back(pUnit->m_strFilePath);
		action_interpretation += "n";
	}
}

void feature::cal_access_frequency(std::shared_ptr<unit> pUnit) {           //record the action(read\write\delete\overwrite) speed.
	string path = pUnit->m_strFilePath;
	auto nSuffixEnum = EventRecordFileioSuffix::GetEnumFromSuffix(EventRecordFileioSuffix::GetSuffix(path));
	
	file_c += 1;
	if (path_hash_table.find(path) != path_hash_table.end()) {
		if (path_hash_table[path].find(pUnit->m_strAction) == path_hash_table[path].end()) {
			path_hash_table[path].insert(pUnit->m_strAction);
		}
		else {
			return;
		}
	}
	else {
		path_hash_table.insert(pair<string, unordered_set<string>>{ path, unordered_set<string>({ pUnit->m_strAction }) });
	}

	if (pUnit->m_strAction == "write") {
		std::get<TFO_WRITE>(m_mapFileEnum2OperationCount[nSuffixEnum]) += 1;
		write_c += 1;
		if (m_setWriteFilePathList.count(path) == 0)
			m_setWriteFilePathList.insert(path);
	}
	else if (pUnit->m_strAction == "delete") {
		std::get<TFO_DELETE>(m_mapFileEnum2OperationCount[nSuffixEnum]) += 1;
		delete_c += 1;
	}
	else if (pUnit->m_strAction == "read") {
		std::get<TFO_READ>(m_mapFileEnum2OperationCount[nSuffixEnum]) += 1;
		read_c += 1;
	}
	else if (pUnit->m_strAction == "overwrite") {
		std::get<TFO_OVERWRITE>(m_mapFileEnum2OperationCount[nSuffixEnum]) += 1;
		overwrite_c += 1;
		if (m_setWriteFilePathList.count(path) == 0)
			m_setWriteFilePathList.insert(path);
	}
	else if (pUnit->m_strAction == "rename") {
		std::get<TFO_RENAME>(m_mapFileEnum2OperationCount[nSuffixEnum]) += 1;
		rename_c += 1;
		if (m_setWriteFilePathList.count(path) == 0)
			m_setWriteFilePathList.insert(path);
	}
	else if (pUnit->m_strAction == "dir_enum") {
		dir_enum_c += 1;
	}
	
	//last_current_time = current_time;
}

/*
void feature::cal_fraction() {                          //record the fraction
	if (file_c <= 2) {
		return;
	}
	write_frac = double(write_c) / double(file_c);
	read_frac = double(read_c) / double(file_c);
	delete_frac = double(delete_c) / double(file_c);
	rename_frac = double(rename_c) / double(file_c);
}
*/

void feature::update_file_size_change(std::shared_ptr<unit> pUnit) {     //record the file change percentage which the process causes.
	//double file_size_change0 = 0, file_size_change1 = 0;
	if (pUnit->m_strAction == "overwrite") {
		for (int i = 0; i < pUnit->m_vctFileSize.size(); i++) {
			if (pUnit->m_vctFileSize[i][0] != 0) {
				file_size_change1 += double(pUnit->m_vctFileSize[i][1] - pUnit->m_vctFileSize[i][0]);
				file_size_change0 += double(pUnit->m_vctFileSize[i][0]);
			}
		}
		if (file_size_change0 != 0) {
			file_size_change = file_size_change1 / file_size_change0;
		}
	}
}


void feature::update_file_magic_number_change(std::shared_ptr<unit> pUnit) {   //update the file magic number's change amount.
	file_magic_number_change += pUnit->m_nFileMagicNumberChange;
}

void feature::update_file_similarity(std::shared_ptr<unit> pUnit) {           //update the file similarity's change amount.
	int32 t = 0;
	for (int i = 0; i < pUnit->m_vctFileSimilarity.size(); i++) {
		t += (100 - pUnit->m_vctFileSimilarity[i]);
	}
	if(!pUnit->m_vctFileSimilarity.empty())
		file_similarity += (int32)(t / (pUnit->m_vctFileSimilarity.size()));
}

void feature::cal_irp_sequence() {                          //update the irp sequence which contains units'actions.
	unordered_set<string> r;
	unordered_set<string> rw;
	unordered_set<string> recorded2;
	unordered_set<string> recorded3;
	for (int i = 0; i < action_path_interpretation.size(); i++) {
		string s = action_path_interpretation[i];
		if (action_interpretation.at(i) == 'r') {
			r.insert(s);
		}
		else if (action_interpretation.at(i) == 'w') {
			if (r.find(s) != r.end()) {
				if (recorded2.find(s) == recorded2.end()) {
					irp2 += 1;
					recorded2.insert(s);
				}
			}
			else {
				rw.insert(s);
			}
		}
		else if (action_interpretation.at(i) == 'o') {
			if (recorded2.find(s) == recorded2.end()) {
				irp2 += 1;
				recorded2.insert(s);
			}
			if (rw.find(s) == rw.end() && r.find(s) != r.end()) {
				if (recorded3.find(s) == recorded3.end()) {
					irp3 += 1;
					recorded3.insert(s);
				}
			}
		}
		else if (action_interpretation.at(i) == 'd') {
			if (rw.find(s) == rw.end() && r.find(s) != r.end()) {
				if (recorded3.find(s) == recorded3.end()) {
					irp3 += 1;
					recorded3.insert(s);
				}
			}
		}
	}
}

/*
//record some key apis' amount.
void feature::update_api(vector<string>&apis)  
{               
	for (int i = 0; i < apis.size(); i++) {
		for (int j = 0; j < ransomapi_need_vec.size(); ++j) {
			if (strstr(apis[i].c_str(), ransomapi_need_vec[j].c_str())) {
				apis_c[j]++;
				break;
			}
		}
	}
}
*/

void feature::update_api()
{
	auto pTemp = CallstackUnit::GetAndClear(pid);
	apis_c.swap(*pTemp);
}


void feature::update_registry()
{
	regcreate_c = RegistryUnit::GetAndClear(pid, registryops::createops);
	regdelete_c = RegistryUnit::GetAndClear(pid, registryops::deleteops);
	regquery_c = RegistryUnit::GetAndClear(pid, registryops::queryops);
	regset_c = RegistryUnit::GetAndClear(pid, registryops::setops);
	m_mapRegEnum2OperationCount = std::move(*EventRecordRegistryPathClassification::GetAndRemoveRegistryInfoByPid(pid));
}

void feature::update_dll()
{
	DllUnit::get(pid, encryptdll_c);
	DllUnit::clear();
}


void feature::makeFeature(std::shared_ptr<process> Process, feature& Feature) {    //do the making feature work
	{
		if (!Process->m_vctUnits.empty())
		{
			vector<std::shared_ptr<unit>> vctTemp;
			vctTemp.swap(Process->m_vctUnits);
			int nUnitsSize = vctTemp.size();

			for (auto iter = vctTemp.begin(); iter != vctTemp.end(); iter++)
			{
				auto unit = (*iter);
				//Feature.update_timestamp(unit);
				Feature.update_file_type(unit);
				Feature.update_action_path_i(unit);
				Feature.cal_access_frequency(unit);
				Feature.update_file_size_change(unit);
				//Feature.cal_system_call(unit);
				Feature.update_file_magic_number_change(unit);
				Feature.update_file_similarity(unit);
				//iter = vctTemp.erase(iter);
			}
			Feature.file_magic_number_change_v = (double)Feature.file_magic_number_change / (double)nUnitsSize;
			Feature.file_similarity_v = (double)Feature.file_similarity / (double)nUnitsSize;
			vctTemp.clear();
		}
	}	

	//Feature.cal_fraction();
	Feature.cal_irp_sequence();
	Feature.update_registry();
	Feature.update_dll();
	Feature.update_api();   //do the api feature work and irp work
	// do not need Process->apis anymore
	//vector<string>().swap(Process->apis); // clear apis
#ifdef ETW_USE_ENTROPY
	Feature.CalcEntropy();
#endif // ETW_USE_ENTROPY

}

void feature::collectFeature(feature& Feature)
{
	ofstream write(train_path, ios::app);
	write << "#pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << " pprocessname: " << Feature.pprocess_name << " time: "<< ToolFunctions::getTime() << endl;
	//cout << "#pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << " pprocessname: " << Feature.pprocess_name << " time: "<< ToolFunctions::getTime() << endl;
	write << Feature.toString() << endl;
	//cout << Feature.toString() << endl;
	write.close();	
}

void feature::InsertTimeStamp(std::string strTimeStamp)
{
	std::lock_guard<std::mutex> lock(g_mutexAllPath);
	ofstream write(all_path, ios::app);
	write << "=====" << strTimeStamp << "=====" << endl;
	write.close();
}

void feature::testFeature(feature& Feature)
{
	//call svm and do the detect work
	DWORD dwMode = ToolFunctions::GetMode();
	bool bRansomDataCollect = Setting::GetInstance().ransom_detector_collect();

	auto pFunIsNormalMode = [&]()
		{
			return dwMode == OPERATION_MODE_NORAML;
		};

	string sp;
	if (bRansomDataCollect)
		sp = Feature.toString();
	else
	//特征添加后该方法可能导致堆栈损坏crash
		sp = scale_by_range(Feature.toString());
	if (sp.empty())
		return;
	int ans = 0;
	bool bPredict = true;
	std::string strMapKey;
	if (Setting::GetInstance().ransom_feature_remove_duplicates() > 0)
	{
		strMapKey = Feature.process_name;
		strMapKey += std::to_string(Feature.pid);
		if (g_umapRemoveDuplicatesFeature.count(strMapKey) > 0
			&& g_umapRemoveDuplicatesFeature[strMapKey] > 0)
		{
			bPredict = false;
			g_umapRemoveDuplicatesFeature[strMapKey]--;
		}
	}

	if (bRansomDataCollect)
		bPredict = false;

	if (bPredict)
		//ans = 1;
		ans = predict(sp);

#ifdef ETW_FEATURE_RECORD_TEST	
	auto pFun = [&](stringstream& ss)
	{
		ss << ans << ",";
		ss << sp << ",";
	};
	Feature.Record2Csv(pFun);
#endif
	
	if (ans == 1
		&& Setting::GetInstance().ransom_feature_remove_duplicates() > 0)
		g_umapRemoveDuplicatesFeature[strMapKey] = Setting::GetInstance().ransom_feature_remove_duplicates();

	if (ans == 1
		&& !RansomFilterRule::GetInstance().ransom_rule_matcher(Feature.pid)
		&& (!RansomFilterRule::GetInstance().white_rule_matcher(Feature.pid)))
	{
		//Get result and send 
		wstring wprocessname = CPykMgrTemplate<CP_UTF8>(Feature.process_name.c_str());
		wstring wpprocessname = CPykMgrTemplate<CP_UTF8>(Feature.pprocess_name.c_str());
		wstring wdetails = CPykMgrTemplate<CP_ACP>(Feature.toString().c_str());
		GUID guid;
		CoCreateGuid(&guid);
		EventRecord* event_record =
			EventRecordManager::GetInstance().ParseRansomDetectorEvent(Feature.pid
				, Feature.ppid
				, wprocessname
				, wpprocessname
				, wdetails
				, guid);
		if (event_record)
		{
			WriteLog4cPlus(INFO_LEVEL, L"check ransom, pid: %d ppid: %d process name: %s parent process name: %s"
				, Feature.pid
				, Feature.ppid
				, wprocessname.c_str()
				, wpprocessname.c_str());
			InitCollector::GetCollector()->PushSendRecord(event_record);
			// add by zxw on 20210513
			bool terminate = Filter::GetInstance().GetRansomTerminate();
			bool stopped = false;

			bool isTrust = false;
			auto iter = process_map::g_umapPid2ProcessInfo.find(Feature.pid);
			if (iter != process_map::g_umapPid2ProcessInfo.end())
			{
				auto info = iter->second;
				auto ppid = info.parent_pid;
				std::wstring parentname = L"";
				auto pter = process_map::g_umapPid2ProcessInfo.find(ppid);
				if (pter != process_map::g_umapPid2ProcessInfo.end())
				{
					parentname = pter->second.process_name;
				}

				CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> RuleTrustProcess = ToolFunctions::GetMSBasicInfoNGEPRule()->m_niRuleTrustProcess;
				CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> RuleFilterProcess = ToolFunctions::GetMSBasicInfoNGEPRule()->m_niRuleFilterProcess;

				isTrust = (CMSBasicInfo_NGEPRuleMatcher::CheckProcess(RuleTrustProcess
					, info.process_name
					, info.process_path
					, info.commandline
					, info.md5
					, info.user
					, parentname)
					|| CMSBasicInfo_NGEPRuleMatcher::CheckProcess(RuleFilterProcess
						, info.process_name
						, info.process_path
						, info.commandline
						, info.md5
						, info.user
						, parentname));
				
			}

            if (terminate  && pFunIsNormalMode() && !isTrust)
            {
                stopped = ToolFunctions::KillProcess(Feature.pid);
			}
			EventRecord* event_terminate = EventRecordManager::GetInstance().ParseRansomTerminateEvent(Feature.pid
				, wprocessname
				, terminate
				, stopped
				, guid);
			if (event_terminate) 
				InitCollector::GetCollector()->PushSendRecord(event_terminate);
		}
		if (Setting::GetInstance().enable_ransom_output())
		{
			ofstream write(output_path, ios::app);
			write << "pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << " pprocessname: " << Feature.pprocess_name << endl;
			write << Feature.toString() << endl;
			write.close();
		}
	}
	if (Setting::GetInstance().enable_ransom_output())
	{
		std::lock_guard<std::mutex> lock(g_mutexAllPath);
		ofstream write(all_path, ios::app);
		std::string Pprocessname = "";
		Pprocessname = ToolFunctions::WStringToString(process_map::g_umapPid2ProcessInfo[Feature.ppid].process_name);
		write << "pid: " << Feature.pid << " processname: " << Feature.process_name << " ppid: " << Feature.ppid << " pprocessname: " << Pprocessname << endl;
		write << Feature.toString() << endl;
		write.close();
	}
}

void feature::getUnits(){                           // get the units, create features and clear the units.
	vector<feature> FeatureList;
	{
		for (vector<std::shared_ptr<process>>::iterator iter = g_vctProcessUnitTree.begin()
			; iter != g_vctProcessUnitTree.end();)
		{
#if 1
			int nUnitsSize = 0;
			auto Process = *iter;
			nUnitsSize = Process->m_vctUnits.size();
			if (nUnitsSize != 0) {
				feature newfeature(Process->pid, Process->path);
				newfeature.ppid = Process->parentPid;
				newfeature.pprocess_name = Process->parentName;
				makeFeature(Process, newfeature);
#ifdef ETW_FEATURE_RECORD_TEST	
				auto pFun = [&](stringstream& ss)
				{
					Process->Record2csv(ss);
				};
				newfeature.Record2Csv(pFun);
#endif
				FeatureList.push_back(newfeature);
				iter++;
			}
			else if (nUnitsSize == 0 && Process->isalive == false) 
				iter = g_vctProcessUnitTree.erase(iter);
			else 
				iter++;
#else
			pprocess Process = *iter;
			feature newfeature(Process->m_nPid, Process->path);
			newfeature.ppid = Process->parentPid;
			newfeature.pprocess_name = Process->parentName;
			makeFeature(Process, newfeature);
			FeatureList.push_back(newfeature);
			iter++;

#endif
		}
	}
	for (auto i : FeatureList)
	{
		if (Setting::GetInstance().enable_ransom_detector())
			testFeature(i);
	}

}

#ifdef ETW_USE_ENTROPY
void feature::CalcEntropy()
{
	if (!m_setWriteFilePathList.empty()
		&& RansomCheck::m_IEtwEntropy != nullptr)
	{
		int nSize = m_setWriteFilePathList.size();
		std::string strInput;
		for (auto i : m_setWriteFilePathList)
		{
			strInput += i;
			strInput += '|';
		}
		
		dEntropy = RansomCheck::m_IEtwEntropy->ICalcEntropyByFileListUtf8(strInput.c_str(), strInput.size());
	}
	else
		dEntropy = 0;
}
#endif // ETW_USE_ENTROPY