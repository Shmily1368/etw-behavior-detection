#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Updated by Cunlin & Ruan
// Created 2018-1
// Updated 2018-4-16


#include <tchar.h>
#include <stdio.h>
#include <unordered_map>
#include <set>
#include "get_device_drive_map.h"
#include "btree.h"
#include <Windows.h>

#define Max_Process_ID 65536
#define MAX_MODULE_LENGTH 65536


class ObtainEntryAddress{
public:
	//ObtainEntryAddress();
	//~ObtainEntryAddress();

	// not used
	// get process information, replace by information from etw events in current version
	//void getAllProcess();
	//DWORD getParentProcessID(DWORD processID);
	//void addTargetProcess(DWORD processID);
	//std::set<DWORD> listSubProcess();

	// get module address using windows apis, replace by information from etw events either.
	//int getModuleBaseAddress(DWORD processID);
	// not used
	//int printModuleBaseAddress(DWORD processID);

	// that could be useful, we may consider it later.
	//int addCommonModulesToSet(std::string folderPath);

	// **** key operation ******
	static btree* getModuleRva(LPVOID hModule);
	static btree* getModuleRvaFromFileName(std::wstring moduleName);

	// print moudle rva to file, would not be used in real-time parsing.
	//int printModuleRva(std::wstring moduleName);
	static void ReadDLLmodualTree(std::string path);
	//int printAllModuleRva();

	//int init();
	//int stop();
	//void getFuncAddr(HMODULE hModule, HMODULE baseAddr);

	static GetDeviceDriveMap m_drivemap;
	// not used
	//static btree rva2FuncNameTree;
	static std::unordered_map<std::wstring, btree> m_umapDLLmodual2Tree;
	static std::unordered_map<std::wstring, std::vector<dllAddress>> m_umapDllmodule2vctDlladdress;
	static btree* m_moduleAddressTree[Max_Process_ID];
	static std::unordered_map<DWORD, dllAddress> m_umapExeNode;
	static std::unordered_map<std::wstring, btree*> m_umapModuleName2Btree;

	static ULONG64 m_ulCurrentModuleSize;

private:
	//std::set<DWORD> m_setTargetProcess;
	static std::wstring m_strCurrentModuleName_;
	// not used
	//static std::wfstream confict_file_;
	//std::string CacheFilePath = "";//"H:\\code\\ETW program\\obtain_dll_enterAddress\\obtain_dll_enterAddress\\dumpfile\\";

	//std::set<std::wstring> m_setModule;
	//std::unordered_map<DWORD, std::wstring> processID2ProcessNameMap;

	//// **** key struct ******
	//std::unordered_map<HMODULE, std::wstring> rva2FuncNameMap;
	//std::unordered_map<std::wstring, HMODULE> moduleName2BaseAddrMap;
};

//bool isEndWith(const wchar_t * str, const wchar_t * end);
bool DllAddress_compare(dllAddress a, dllAddress b);