#include "stdafx.h"
#include"unit.h"
#include "event.h"
#include "processTree.h"
#include <unordered_map>
#include <iostream>
#include <fstream>
#include <sys\stat.h>
#include <stdio.h>
#include <stdlib.h>
#include "setting.h"

unordered_map<string, int> unit::event_dict = { {"FileIoCreate",0},{"FileIoRead",1},{"FileIoWrite",2},{"FileIoDelete",3},{"FileIoRename",4},{"FileIoDirEnum",5},{"FileIoCleanup",6} };

unordered_map<int, std::shared_ptr<process>> g_umapProcessTree;                         //the tree which contains live processes
vector<std::shared_ptr<process>> g_vctProcessUnitTree;                                 //the vector which contains the processes which has unit to transfer to feature and detect.
unordered_map<string, vector<string>> g_umapFileMap;                    //the map which contains the files' sdhash.
int32 file_c = 0;

string g_strComparePath = "tool\\sdhash\\sdhash.exe -c file.tmp -t 0";

string trim(string s) {
	size_t n = s.find_last_not_of("\r\n");
	if (n != string::npos) {
		s.erase(n + 1, s.size() - n);
	}
	n = s.find_first_not_of(" \r\n\t");
	if (n != string::npos) {
		s.erase(0, n);
	}
	return s;
}

void processEvent(event& singleEvent) {

	if (singleEvent.EventName != "") 
	{
		if (singleEvent.EventName == "ProcessDCStart" 
			|| singleEvent.EventName == "ProcessStart") 
		{
			//当前进程节点
			auto newProcess = std::make_shared<process>(
				singleEvent.arguments.ProcessId
				, singleEvent.arguments.ImageFileName
				, singleEvent.TimeStamp);
			newProcess->parentPid = singleEvent.processID;
			
			if (g_umapProcessTree.find(singleEvent.processID) == g_umapProcessTree.end()) 
			{
				//未找到父进程节点，构造父进程节点
				auto parentProcess = std::make_shared<process>(
					singleEvent.processID);
				parentProcess->addSon(newProcess);
				newProcess->setParent(parentProcess);
				newProcess->parentName = parentProcess->path;
				//插入父子进程节点
				g_vctProcessUnitTree.push_back(parentProcess);
				g_vctProcessUnitTree.push_back(newProcess);
				g_umapProcessTree.insert(std::make_pair(parentProcess->pid ,parentProcess));
				g_umapProcessTree.insert(std::make_pair(newProcess->pid, newProcess));
#ifdef ETW_UNIT_RECORD_TEST	
				auto pFun = [&](stringstream& ss)
				{
					singleEvent.Record2csv(ss);
				};
				newProcess->Record2Csv(pFun);
#endif
			}
			else 
			{
				//父进程节点已存在
				std::shared_ptr<process> parentProcess = g_umapProcessTree[singleEvent.processID];
				newProcess->setParent(parentProcess);
				newProcess->parentName = parentProcess->path;
				parentProcess->addSon(newProcess);
				if (g_umapProcessTree.find(newProcess->pid) != g_umapProcessTree.end())
				{
					//找到了当前进程节点
					g_umapProcessTree[newProcess->pid].swap(newProcess);
				}
				else
				{
					//未找到当前进程节点
					g_umapProcessTree.insert(std::make_pair(newProcess->pid, newProcess));
					g_vctProcessUnitTree.push_back(newProcess);
				}
			}
		}
		else if (singleEvent.EventName == "ProcessEnd" || singleEvent.EventName == "ProcessDCEnd") {
			if (g_umapProcessTree.find(singleEvent.processID) != g_umapProcessTree.end()) {
				std::shared_ptr<process> Process = g_umapProcessTree[singleEvent.arguments.ProcessId]; 
				//when isalive == false, remove the process from processTree
				Process->isalive = false;                     
				//when units.size()==0 and isalive == false, remove the process from processUnitTree and delete the process
#ifdef ETW_UNIT_RECORD_TEST	
				auto pFun = [&](stringstream& ss)
				{
					singleEvent.Record2csv(ss);
				};
				Process->Record2Csv(pFun);
#endif
				g_umapProcessTree.erase(singleEvent.arguments.ProcessId);
			}
		}
		else {
			std::shared_ptr<process> Process = nullptr;
			{
				if (g_umapProcessTree.find(singleEvent.processID) != g_umapProcessTree.end()) {
					Process = g_umapProcessTree[singleEvent.processID];
				}
				else {
					//return;
					Process = std::make_shared<process>(singleEvent.processID);
					g_umapProcessTree.insert(std::make_pair(Process->pid, Process));
					g_vctProcessUnitTree.push_back(Process);
				}
			}
			if (singleEvent.EventName == "FileIoCreate") 
			{
				auto pNewUnit = std::make_shared<unit>(singleEvent.processID, singleEvent.TimeStamp, Process->path, singleEvent.arguments.OpenPath);
				pNewUnit->m_vctEventsName.push_back(singleEvent.EventName);
				Process->m_umapFileObject2EventUnits.insert(std::make_pair(singleEvent.arguments.FileObject, pNewUnit));
#ifdef ETW_UNIT_RECORD_TEST	
				auto pFun = [&](stringstream& ss)
				{
					singleEvent.Record2csv(ss);
				};
				pNewUnit->Record2Csv(pFun);
#endif
			}
			else if (Process->m_umapFileObject2EventUnits.find(singleEvent.arguments.FileObject) != Process->m_umapFileObject2EventUnits.end())
			{
				auto Unit = Process->m_umapFileObject2EventUnits[singleEvent.arguments.FileObject];
				//std::shared_ptr<unit> Unit = std::make_shared<unit>(Process->tempunits[singleEvent.arguments.FileObject]);
				Unit->m_vctEventsName.push_back(singleEvent.EventName);
				do
				{
					if (singleEvent.EventName == "FileIoRead") {
						Unit->m_nReadBytes += singleEvent.arguments.IoSize;
					}
					else if (singleEvent.EventName == "FileIoWrite") {
						Unit->m_nWriteBytes += singleEvent.arguments.IoSize;
						event FileIoChange("FileIoChange", singleEvent.processID, singleEvent.TimeStamp);
						FileIoChange.arguments.action = 2;
						FileIoChange.arguments.FileObject = singleEvent.arguments.FileObject;
						if (Unit->m_strFilePath.empty())
							break;
						string openpath = Unit->m_strFilePath;
						FileIoChange.arguments.OpenPath = openpath;        //get the file's sdhash, magic number and filesize. 
						if (openpath != "" 
							&& openpath.find("file.tmp") == -1 
							&& openpath.find("output.out") == -1 
							&& openpath.find("allfeature.out") == -1 
							&& openpath.find("features.all") == -1) 
						{
							struct _stat info;
							if (_stat(openpath.c_str(), &info) != 0) {
								//cout << "get file size fail:" << openpath << endl;
								break;
							}
							FileIoChange.arguments.size = info.st_size;
							ifstream input(openpath, ios::binary);
							char magic[5] = { 0 };
							if (input.is_open()) {
								input.seekg(0, ios::beg);
								input.read((char*)magic, sizeof(magic) - 1);
							}
							else {
								//cout << "get file magic number fail:" << openpath << endl;
								break;
							}
							FileIoChange.arguments.magic = magic;         //用文件读取字节直接代替file.exe
							processEvent(FileIoChange);    //call fileiochange when write events happen.
						}

					}
					else if (singleEvent.EventName == "FileIoChange")
					{
						if (g_umapFileMap.find(singleEvent.arguments.OpenPath) != g_umapFileMap.end()) {
							vector<string>& file = g_umapFileMap[singleEvent.arguments.OpenPath];
							int32 oldsize = atoi(file[0].c_str());
							vector<int32> size = { oldsize, singleEvent.arguments.size };
							Unit->m_vctFileSize.push_back(size);
							file[0] = to_string(singleEvent.arguments.size);
							if (file[1] != singleEvent.arguments.magic 
								&& file[1] != "" 
								&& singleEvent.arguments.magic != "") 
								Unit->m_nFileMagicNumberChange += 1;
							
							if (singleEvent.arguments.magic != "") 
								file[1] = singleEvent.arguments.magic;
							
							if (file[2] != "" 
								&& singleEvent.arguments.sdhash != "") {
								ofstream tempfile("file.tmp");
								tempfile << trim(file[2]) << endl << trim(singleEvent.arguments.sdhash);
								tempfile.close();
								FILE* fp = _popen(g_strComparePath.c_str(), "r");
								if (!fp) {
									perror("sdhash compare popen error");
									_pclose(fp);
								}
								else {
									string temp;
									char ts[1024];
									while ((fgets(ts, 1024, fp)) != NULL)
									{
										temp += ts;
									}
									if (temp.size() >= 3 && (atoi(temp.substr(temp.size() - 3, 3).c_str()) > 0 || temp.substr(temp.size() - 3, 3) == "000")) {
										Unit->m_vctFileSimilarity.push_back(atoi(temp.substr(temp.size() - 3, 3).c_str()));
									}
									_pclose(fp);
								}
							}
							if (singleEvent.arguments.sdhash != "") {
								file[2] = singleEvent.arguments.sdhash;
							}
						}
						else {
							vector<string> file = { to_string(singleEvent.arguments.size) ,singleEvent.arguments.magic ,singleEvent.arguments.sdhash };
							if (g_umapFileMap.size() > 100000) {
								g_umapFileMap.erase(g_umapFileMap.begin());
							}
							g_umapFileMap.insert(pair<string, vector<string>>{ singleEvent.arguments.OpenPath, file });
							vector<int32> size = { singleEvent.arguments.size, singleEvent.arguments.size };
							Unit->m_vctFileSize.push_back(size);
							file_c += 1;
							//Unit->file_magic_number_change += 1;
							Unit->m_vctFileSimilarity.push_back(100);
						}
					}
					else if (singleEvent.EventName == "FileIoCleanup")
					{
						vector<int32> eventint;
						Unit->eventToInt(eventint);
						Unit->setAction(eventint);
						if (Unit->m_strAction == "normal") {
						Process->m_umapFileObject2EventUnits.erase(singleEvent.arguments.FileObject);
							break;
						}

						{
							Process->m_vctUnits.push_back(Unit);
						}
						Process->m_umapFileObject2EventUnits.erase(singleEvent.arguments.FileObject);
					}
					else if (singleEvent.EventName == "FileIoRename") {
						Unit->m_strFilePath = singleEvent.arguments.IrpPtr;
					}
				} while (false);
#ifdef ETW_UNIT_RECORD_TEST	
				auto pFun = [&](stringstream& ss)
				{
					singleEvent.Record2csv(ss);
				};
				Unit->Record2Csv(pFun);
#endif
			}
		}
		
	}
}