#include "stdafx.h"
#include "callstack_pruning.h"
#include "event_record_manager.h"
#include "obtain_entry_address.h"
#include "event_record_callstack.h"
#include "event_record.h"
#include "tool_functions.h"
#include "init_collector_local_collect.h"
#include "init_collector_online_parse.h"
#include "init_collector.h"
#include "setting.h"
#include "callstack_pruning.h"
#include "phf_detector.h"
#include "thread_task_manager.h"
#include "filter.h"
#include <evntrace.h>
#include <tdh.h>
#include <Windows.h>
#include <sstream>
#include <unordered_set>
#include "CallstackUnit.h"

using namespace std;
ULONG64 EventRecordCallstack::parse_api_level_number = 0;

std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::process_address_cache;
std::unordered_map<DWORD, std::unordered_map<ULONG64, std::string>>EventRecordCallstack::process_API_address_cache;
std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::process_address_useless_cache;
std::unordered_map<DWORD, std::unordered_set<ULONG64>>EventRecordCallstack::APIaddress_keepon_cache;

std::function<void(EventRecordCallstack*)> EventRecordCallstack::m_funParse = nullptr;
bool EventRecordCallstack::m_bRansomDetect = false;
std::unordered_map<ULONG64, int> EventRecordCallstack::m_umapRansomAPIIndexCache;
std::unordered_map<std::string, std::vector<ULONG64>> EventRecordCallstack::m_umapRansomDllCache;


#ifdef USE_RAW_SIGNATURE

STRING_STRING_UMAP api_filename_mapping = 
{
	{"GetKeyState", "user32.dll"},
	{"GetKeyboardState", "user32.dll"},
	{"GetAsyncKeyState", "user32.dll"},
	{"NtUserGetKeyState", "win32u.dll"},		//Win10 API;
	{"NtUserGetKeyboardState", "win32u.dll"},	//Win10 API;
	{"GetDC", "user32.dll"},
	{"NtUserGetDC", "win32u.dll"},
	{"BitBlt", "gdi32.dll"},
	{"StretchBlt", "gdi32.dll"},
	{"CreateDIBSection", "gdi32.dll"},			//Win10 API;
	{"CreateCompatibleDC", "gdi32.dll"},
	{"CreateCompatibleBitmap", "gdi32.dll"},
	{"SetBkColor", "gdi32.dll"},
	{"SelectObject", "gdi32.dll"},
	{"SelectObjectImpl", "gdi32full.dll"},		//Win10 API;
	{"NtGdiSelectBitmap", "win32u.dll"},			//Win10 API;
	{"ZwCreateNamedPipeFile", "ntdll.dll"},
	{"CreatePipe", "KernelBase.dll"},
	{"ZwOpenProcess", "ntdll.dll"},
	{"OpenProcess", "KernelBase.dll"},
	{"ZwAllocateVirtualMemory", "ntdll.dll"},
	{"VirtualAllocEx", "KernelBase.dll"},
	//{"VirtualAlloc", "KernelBase.dll"},
	{"ZwWriteVirtualMemory", "ntdll.dll"},
	{"WriteProcessMemory", "KernelBase.dll"},
	{"ZwQueryInformationProcess","ntdll.dll"},
	{"K32GetProcessImageFileName","kernel32.dll"},
	{"ZwDeviceIoControlFile","ntdll.dll"},
	{"CryptImportKey","cryptsp.dll"},
};

STRING_SET api_need_set = 
{
	"GetKeyState",
	"GetKeyboardState",
	"GetAsyncKeyState",
	"NtUserGetKeyState",			//Win10 API;
	"NtUserGetKeyboardState",		//Win10 API;
	"GetDC",
	"NtUserGetDC",					//Win10 API;
	"NtGdiCreateDIBSection",		//Win10 API;
	"CreateCompatibleDC",
	"CreateCompatibleBitmap",
	"CreateDIBSection",				//Win10 API;
	"NtGdiCreateCompatibleDC",		//Win10 API;
	"NtGdiCreateCompatibleBitmap",	//Win10 API;
	"BitBlt",
	"NtGdiBitBlt",					//Win10 API;
	"StretchBlt",
	"NtGdiStretchBlt",				//Win10 API;
	"SetBkColor", //1973703913(\\Windows\\SysWOW64\\gdi32.dll:SetBkColor),1973702794(\\Windows\\SysWOW64\\gdi32.dll:SelectObject)
	"NtGdiSelectBitmap",			//Win10 API;
	"SelectObject",
	"SelectObjectImpl",				//Win10 API;
	"NtGdiSelectBitmap",			//Win10 API;
	"ZwCreateNamedPipeFile",
	"CreatePipe",
	"ZwOpenProcess",
	"OpenProcess",
	"ZwAllocateVirtualMemory",
	"VirtualAllocEx",
	//"VirtualAlloc",
	"ZwWriteVirtualMemory",
	"WriteProcessMemory",
	"K32GetProcessImageFileName",
	"CryptImportKey",
};

#else

STRING_STRING_UMAP api_filename_mapping;
STRING_SET api_need_set;

#endif //USE_RAW_SIGNATURE;

/*
STRING_STRING_UMAP ransomapi_filename_mapping
{
	{"CryptImportKey", "Advapi32.dll"},
	{"CryptDecrypt", "Advapi32.dll"},
	{"CryptDeriveKey", "Advapi32.dll"},
	{"GetUserName", "Advapi32.dll" },
	{"CryptGenKey", "Advapi32.dll"},
	{"CryptDecodeObject", "Crypt32.dll"},
	{"CryptImportPublicKeyInfo", "Crypt32.dll"},
	{"NdrClientCall2", "Rpcrt4.dll"},
	{"InternetOpen", "Wininet.dll"},
	{"Socket", "Ws2_32.dll"},
};
*/

extern const int g_nRansomapi_maxsize = 55;  // extern����

//not used
//extern const STRING_VECTOR ransomapi_need_vec
//{
//	"CryptImportKey",
//	"CryptDecrypt",
//	"CryptDeriveKey",
//	"GetUserName",
//	"GetUserNameA",
//	"GetUserNameW",
//	"LsaGetUserName",
//	"NpGetUserName",
//	"CryptGenKey",
//	"CryptDecodeObject",
//	"CryptDecodeObjectEx",
//	"CryptDecodeMessage",
//	"CryptImportPublicKeyInfo",
//	"CryptImportPublicKeyInfoEx",
//	"CryptImportPublicKeyInfoEx2",
//	"NdrClientCall",
//	"NdrClientCall2",
//	"NdrClientCall3",
//	"NdrpClientCall2",
//	"InternetOpen",
//	"InternetOpenA",
//	"InternetOpenW",
//	"InternetOpenUrlA",
//	"InternetOpenUrlW",
//	"WSASocket",
//	"WSASocketA",
//	"WSASocketW",
//};

extern const unordered_map<std::string, int> ransomapi_need_map
{
	{"CryptImportKey",				0 },	//advapi32
	{"CryptDecrypt",				1 },	//advapi32
	{"CryptDeriveKey",				2 },	//advapi32
	{"GetUserName",					3 },	//advapi32
	{"GetUserNameA",				3 },	//advapi32
	{"GetUserNameW",				3 },	//advapi32
	{"LsaGetUserName",				3 },	//advapi32
	{"NpGetUserName",				3 },	//advapi32
	{"CryptGenKey",					4 },	//advapi32
	{"CryptDecodeObject",			5 },	//crypt32
	{"CryptDecodeObjectEx",			5 },	//crypt32
	{"CryptDecodeMessage",			5 },	//crypt32
	{"CryptImportPublicKeyInfo",	6 },	//crypt32
	{"CryptImportPublicKeyInfoEx",	6 },	//crypt32
	{"CryptImportPublicKeyInfoEx2",	6 },	//crypt32
	{"NdrClientCall",				7 },	//rpcrt4
	{"NdrClientCall2",				7 },	//rpcrt4
	{"NdrClientCall3",				7 },	//rpcrt4
	{"NdrpClientCall2",				7 },	//rpcrt4
	{"InternetOpen",				8 },
	{"InternetOpenA",				8 },
	{"InternetOpenW",				8 },
	{"InternetOpenUrlA",			8 },
	{"InternetOpenUrlW",			8 },
	{"WSASocket",					9 },
	{"WSASocketA",					9 },
	{"WSASocketW",					9 },
	{"GdipSaveImageToFile",			10 },	//gdiplus
	{ "MoveFileWithProgressW ",11 },	//kernel32
	{ "MoveFileWithProgressA ",11 },	//kernel32
	{ "NtCreateFile",12 },	//nt
	{ "ZwCreateFile",12 },	//nt
	{ "CreateFileA",12 },	//kernel32
	{ "CreateFileW",12 },	//kernel32
	{ "CreateFileMappingA",12 },	//kernel32
	{ "CreateFileMappingW",12 },	//kernel32
	{ "CreateFile2",12 },	//kernel32
	{ "CreateFileMappingNumaA",12 },	//kernel32
	{ "CreateFileMappingNumaW",12 },	//kernel32
	{ "CreateFileMappingFromApp",12 },	//kernel32
	{ "CreateFileTransactedA",12 },	//kernel32
	{ "CreateFileTransactedW",12 },	//kernel32
	{ "LZCreateFileW",12 },	//kernel32
	{ "NtWriteFile",13 },	//nt
	{ "ZwWriteFile",13 },	//nt
	{ "NtWriteFileGather",14 },	//nt
	{ "ZwWriteFileGather",14 },	//nt
	{ "NtWriteRequestData",15 },	//nt
	{ "ZwWriteRequestData",15 },	//nt
	{ "NtWriteVirtualMemory",16 },	//nt
	{ "NtWow64WriteVirtualMemory64",16 },	//nt
	{ "ZwWriteVirtualMemory",16 },	//nt
	{ "ZwWow64WriteVirtualMemory64",16 },	//nt
	{ "SetFileAttributesA",17 },	//kernel32
	{ "SetFileAttributesW",17 },	//kernel32
	{ "SetFileAttributesTransactedA",18 },	//kernel32
	{ "SetFileAttributesTransactedW", 18 },	//kernel32
	{ "GetDiskFreeSpaceW",19 },	//kernel32
	{ "GetDiskFreeSpaceExW",19 },	//kernel32
	{ "GetDiskFreeSpaceA",19 },	//kernel32
	{ "GetDiskFreeSpaceExA",19 },	//kernel32
	{ "GetComputerNameW",20 },	//kernel32
	{ "GetComputerNameExW",20 },	//kernel32
	{ "GetComputerNameA",20 },	//kernel32
	{ "GetComputerNameExA",20 },	//kernel32
	{ "GlobalMemoryStatus",21 },	//kernel32
	{ "GlobalMemoryStatusEx",21 },	//kernel32
	{ "NtWow64AllocateVirtualMemory64",22 },	//nt
	{ "NtAllocateVirtualMemory",22 },	//nt
	{ "ZwWow64AllocateVirtualMemory64",22 },	//nt
	{ "ZwAllocateVirtualMemory",22 },	//nt
	{ "NtMapViewOfSection",23 },	//nt
	{ "ZwMapViewOfSection",23 },	//nt
	{ "NtProtectVirtualMemory",24 },	//nt
	{ "NtUnmapViewOfSection",25 },	//nt
	{ "NtUnmapViewOfSectionEx",25 },	//nt
	{ "ZwUnmapViewOfSection",25 },	//nt
	{ "ZwUnmapViewOfSectionEx",25 },	//nt
	{ "WriteProcessMemory",26 },	//kernel32
	{ "LdrGetDllHandle",27 },	//nt
	{ "LdrGetDllHandleEx",27 },	//nt
	{ "LdrGetDllHandleByName",27 },	//nt
	{ "LdrGetDllHandleByMapping",27 },	//nt
	{ "CreateProcessInternalW",28 },	//kernel32
	{ "CreateProcessInternalA",28 },	//kernel32
	{ "CreateProcessAsUserW",29 },	//kernel32
	{ "CreateProcessAsUserA",29 },	//kernel32
	{ "CreateProcessW",30 },	//kernel32
	{ "CreateProcessA",30 },	//kernel32
	{ "NtGetContextThread",31 },	//nt
	{ "ZwGetContextThread",31 },	//nt
	{ "NtResumeThread",32 },	//nt
	{ "NtAlertResumeThread",32 },	//nt
	{ "ZwResumeThread",32 },	//nt
	{ "ZwAlertResumeThread",32 },	//nt
	{ "NtSetContextThread",33 },	//nt
	{ "ZwSetContextThread",33 },	//nt
	{ "NtTerminateProcess",34 },	//nt
	{ "ZwTerminateProcess",34 },	//nt
	{ "TerminateProcess",34 },	//kernel32
	{ "Process32NextW",35 },	//kernel32
	{ "Process32Next",35 },	//kernel32
	{ "NtLoadDriver",36 },	//nt
	{ "ZwLoadDriver",36 },	//nt
	{ "NtSetValueKey",37 },	//nt
	{ "ZwSetValueKey",37 },	//nt
	{ "RtlpNtSetValueKey",37 },	//nt
	{ "RegOpenKeyExW",38 },	//kernel32
	{ "RegOpenKeyExA",38 },	//kernel32
	{ "RegQueryValueExW",39 },	//kernel32
	{ "RegQueryValueExA",39 },	//kernel32
	{ "RegSetValueExW",40 },	//kernel32
	{ "RegSetValueExA",40 },	//kernel32
	{ "NtCreateKey",41 },	//nt
	{ "ZwCreateKey",41 },	//nt
	{ "NtCreateKeyTransacted",42 },	//nt
	{ "ZwCreateKeyTransacted",42 },	//nt

	//{ "CryptGenKey",4 },
	{ "CryptExportKey",43 },	//advapi32
	{ "LookupPrivilegeValueW",44 },	//advapi32
	{ "LookupPrivilegeValueA",44 },	//advapi32
	{ "CryptHashData",45 },	//advapi32
	{ "CreateServiceW",46 },	//advapi32
	{ "CreateServiceA",46 },	//advapi32
	{ "EnumServicesStatusW",47 },	//advapi32
	{ "EnumServicesStatusA",47 },	//advapi32
	{ "EnumServicesStatusExW",47 },	//advapi32
	{ "EnumServicesStatusExA",47 },	//advapi32
	{ "SetWindowsHookW",48 },	//user32
	{ "SetWindowsHookA",48 },	//user32
	{ "SetWindowsHookExW",48 },	//user32
	{ "SetWindowsHookExA",48 },	//user32
	{ "FindWindowW",49 },	//user32
	{ "FindWindowA",49 },	//user32
	{ "FindWindowExW",49 },	//user32
	{ "FindWindowExA",49 },	//user32
	{ "NtQuerySystemInformation",50 },	//nt
	{ "NtQuerySystemInformationEx",50 },	//nt
	{ "ZwQuerySystemInformation",50 },	//nt
	{ "ZwQuerySystemInformationEx",50 },	//nt
	{ "DeviceIoControl",51 },	//kernel32
	{ "GetComputerName",52 },	//kernel32
	{ "GetComputerNameA",52 },	//kernel32
	{ "GetComputerNameW",52 },	//kernel32
	{ "GetComputerNameExA",52 },	//kernel32
	{ "GetComputerNameExW",52 },	//kernel32
	{ "GetFileAttributesA",53 },	//kernel32
	{ "GetFileAttributesW",53 },	//kernel32
	{ "GetFileAttributesExA",53 },	//kernel32
	{ "GetFileAttributesExW",53 },	//kernel32
	{ "GetFileAttributesTransactedA",53 },	//kernel32
	{ "GetFileAttributesTransactedW",53 },	//kernel32
	{ "NtQueryDirectoryFile",54 },	//nt
	{ "NtQueryDirectoryObject",54 },	//nt
	{ "ZwQueryDirectoryFile",54 },	//nt
	{ "ZwQueryDirectoryObject",54 },	//nt
	{ "FindFirstFileA",54 },	//kernel32
	{ "FindFirstFileW",54 },	//kernel32
	{ "FindFirstFileExA",54 },	//kernel32
	{ "FindFirstFileExW",54 },	//kernel32
	{ "FindFirstFileNameTransactedW",54 },	//kernel32
	{ "FindFirstFileNameW",54 },	//kernel32
	{ "FindFirstFileTransactedA",54 },	//kernel32
	{ "FindFirstFileTransactedW",54 },	//kernel32
	{ "FindNextFileA",54 },	//kernel32
	{ "FindNextFileW",54 },	//kernel32
	{ "FindNextFileNameW",54 },	//kernel32

	//{ "ShellExecuteExW",16 },	//todo

};

STRING_SET api_ntdll_need_set_win7 = 
{
	"ZwCreateNamedPipeFile",
	"ZwOpenProcess",
	"ZwAllocateVirtualMemory",   //process injection
	"ZwWriteVirtualMemory",
	"ZwQueryObject",
	"ZwQueryInformationProcess",
    "ZwFlushInstructionCache",
};

STRING_SET api_ntdll_need_set_win10 =
{
	"ZwCreateNamedPipeFile",
	"ZwOpenProcess",
	"ZwWriteVirtualMemory",
	"ZwQueryInformationProcess",
    "ZwFlushInstructionCache",
};

STRING_SET api_keepon_set_win7 = 
{
	"ZwFreeVirtualMemory",		// remotedesktop, GdipSaveImageToStream;
	"ZwOpenSection",			// audiorecord, waveinopen;
	"ZwWaitForSingleObject",	// waveinaddbuffer;
	"ZwDeviceIoControlFile",
    "ZwAllocateVirtualMemory",
    "ZwFlushInstructionCache",
    "ZwProtectVirtualMemory",
    "ZwLockVirtualMemory",
};

STRING_SET api_keepon_set_win10 =
{
	"ZwFreeVirtualMemory",		// remotedesktop, GdipSaveImageToStream;
	"ZwOpenSection",			// audiorecord, waveinopen;
	"ZwWaitForSingleObject",	// waveinaddbuffer;
	"ZwAllocateVirtualMemory",  // VirtualAllocExNuma;
	"ZwDeviceIoControlFile",
    "ZwFlushInstructionCache",
    "ZwProtectVirtualMemory",
    "ZwLockVirtualMemory",
};

EventRecordCallstack::EventRecordCallstack(PEVENT_RECORD raw_rec)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordCallstack);

	ULONG64* p_data = (ULONG64*)raw_rec->UserData;
	USHORT data_size = raw_rec->UserDataLength;
	ULONG64 etw_stack_address;

	m_eventIdentifier = EventIdentifier(raw_rec->EventHeader.ProviderId.Data1, raw_rec->EventHeader.EventDescriptor.Opcode);

	m_ulTimeStamp = *p_data++;
	m_dwProcessId = *(DWORD*)p_data;
	m_dwThreadId = *((DWORD*)p_data + 1);
	p_data++;

	if (m_dwProcessId == 0 || m_dwProcessId == 4 || m_dwProcessId == GetCurrentProcessId()) 
	{
		return;
	}
	USHORT stack_size = data_size / 8 - 2;
	for (int i = 0; i < stack_size; i++)
	{
		etw_stack_address = *(p_data + i);
		entry_address_vector_[i] = etw_stack_address;
		++vector_size;
		if (etw_stack_address >= 0xfffff00000000000) // kernel address
		{
			kernel_start = i;
		}
	}

	return;
}

EventRecordCallstack::EventRecordCallstack(int pid, int tid, ULONG64 timestamp)
{
	OBJECT_MEMORY_MONITOR_CTOR(EventRecordCallstack);

	m_dwThreadId = tid;
	m_dwProcessId = pid;
	m_ulTimeStamp = timestamp;
	m_eventIdentifier.provider_id(ETWStackWalk);
	m_eventIdentifier.opcode(32);
	m_strCallstack = "";
	label_ = "";
}

EventRecordCallstack::~EventRecordCallstack()
{
	OBJECT_MEMORY_MONITOR_DTOR(EventRecordCallstack);
}

void EventRecordCallstack::Init()
{
	m_bRansomDetect = Setting::GetInstance().enable_ransom_detector();
	if (m_bRansomDetect)
	{
		m_funParse = ParseTopLevelAPIwithRansomAPI;
	}
	else if(Setting::GetInstance().local_detector_parse())
	{
		m_funParse = ParseFullStackWithVector;
	}
	else if (Setting::GetInstance().optimize_api_parse())
	{
		switch (ToolFunctions::GetSystemOs())
		{
		case EM_OsVersion::WIN7:		m_funParse = ParseTopLevelAPIwithOptimize; break;
		case EM_OsVersion::WIN10:		m_funParse = ParseTopLevelAPIwithOptimizeWin10; break;
		case EM_OsVersion::WS2012_R2:	m_funParse = ParseTopLevelAPIwithOptimizeWS2012R2; break;
		default:	break;
		}
	}
	else
	{
		switch (ToolFunctions::GetSystemOs())
		{
		case EM_OsVersion::WIN7:
		case EM_OsVersion::WIN10:		m_funParse = std::bind(ParseTopLevelAPIwithRunqinTrick, std::placeholders::_1, 0); break;
		case EM_OsVersion::WS2012_R2:	m_funParse = std::bind(ParseTopLevelAPIwithRunqinTrickWS2012R2, std::placeholders::_1, 0); break;
		default:	break;
		}
	}
}

int EventRecordCallstack::parse() 
{
	if (!m_bRansomDetect && Setting::GetInstance().local_detector_parse())
	{
		ParseFullStackWithVector(this);
		PhfDetector::GetInstance().ParseThread2ApisFullWithVec(this);
	}
	else if (m_bRansomDetect)
	{
		ParseTopLevelAPIwithRansomAPI(this);
	}
	else if(m_funParse) {
		m_funParse(this);
	}
	
	return 0;
}

bool EventRecordCallstack::Output()
{

	if (m_bRansomDetect)
	{
		if (!m_bUseless)
		{
			QPCtimeToSystime();
			if (InitCollector::GetCollector())
				InitCollector::GetCollector()->PushSendRecord(this);
			return true;	
		}
		else
		{
			return false;
		}
	}
	else if (Setting::GetInstance().local_detector_parse())
	{
		PhfDetector::GetInstance().OutputDetectPhf();
		EventRecordManager::GetInstance().RecycleEventRecord(this);
	}
	else
	{
		if (InitCollector::GetCollector()) {
			QPCtimeToSystime();
			InitCollector::GetCollector()->PushSendRecord(this);
		}
	}

	return true;
}

void EventRecordCallstack::InitApiConfiguration()
{
#ifndef USE_RAW_SIGNATURE

	std::fstream fp;
	String read_str;

	fp.open("api_configuration/api_filename_mapping", ios::in | ios::binary);
	while (getline(fp, read_str))
	{
		STRING_VECTOR mapping_info;
		StringUtil::split(ToolFunctions::DecryptStr(read_str), ':', mapping_info);
		api_filename_mapping.insert(std::make_pair(mapping_info[0], mapping_info[1]));
	}
	fp.close();

	fp.open("api_configuration/api_need_set", ios::in | ios::binary);
	while (getline(fp, read_str))
	{
		api_need_set.insert(ToolFunctions::DecryptStr(read_str));
	}
	fp.close();

#endif // !USE_RAW_SIGNATURE
}

void EventRecordCallstack::SetLabel(const String& label)
{
	if (label_ == "")
		label_ = label;
	else
		label_ += string(",") + label;
}

void EventRecordCallstack::SetCallstack(const String& callstack)
{
	m_strCallstack = callstack;
}

String EventRecordCallstack::GetLabel()
{
	return label_;
}

String EventRecordCallstack::GetOutputInfo()
{
	if (!m_bRansomDetect  && Setting::GetInstance().local_detector_parse())
	{
		return label_;
	}
	else
	{
		return m_strCallstack;
	}
}

/*  cache for the apis on ransom detect
	api is related to the dll imageload
	we will delete the api cache when unload the dll image */

void EventRecordCallstack::UnCacheRansomAPI(std::string dllname)
{
	auto iter = m_umapRansomDllCache.find(dllname);
	if (iter == m_umapRansomDllCache.end()) return;
	for (auto apiAdr : iter->second)
	{
		m_umapRansomAPIIndexCache.erase(apiAdr);
	}
	m_umapRansomDllCache.erase(iter);
}

void EventRecordCallstack::ParseTopLevelAPIwithRansomAPI(EventRecordCallstack* ev)
{
	std::string callstack_;
	DWORD pid = ev->m_dwProcessId;
	ev->m_bUseless = true;  // donot output in ransom detect
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree 
		|| ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
		return;
	int  iter = 0;
	int length = ev->vector_size;
	if (length == 0) 
		return; 

	const auto& address_stack = ev->entry_address_vector_;
	String& ev_callstack = ev->m_strCallstack;//blank or ox address
	if (!ev_callstack.empty() || iter == length)
		return;

	unsigned long long exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	unsigned long long exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;

	for (; iter != length; iter++) {
		unsigned long long temp_iter = address_stack[iter];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_) 
			break;
	}
	do {
		if (ev_callstack.empty() && length) {
			// while (--iter, iter >= 0  && address_stack[iter] < 0xfffff00000000000) 
			// 暂时只解析第一层的API，这里需要 --iter
			--iter;
			if (iter >= 0 && address_stack[iter] < 0xfffff00000000000) {
				ULONG64 temp_iter = address_stack[iter];
				auto riter = m_umapRansomAPIIndexCache.find(temp_iter);
				if (riter != m_umapRansomAPIIndexCache.end()) {
					auto ApiIndex = riter->second;
					if (ApiIndex != -1) {
						CallstackUnit::increase(ev->get_process_id_(), ApiIndex);
					}
					break;
				}
				callstack_ = ConvertAddress2APIName(ev, temp_iter);
//#ifdef ETW_EVENT_RECORD_TEST	
//				ev->Record2csv("ConvertAddress2APIName");
//				ev->Record2csv(callstack_);
//#endif
				if (!callstack_.empty() && strstr(callstack_.c_str(), "NOOAPI") == nullptr 
					&& strstr(callstack_.c_str(), "NOMODULE") == nullptr 
					&& strstr(callstack_.c_str(), "NOAPI") == nullptr)
				{		
//#ifdef ETW_EVENT_RECORD_TEST	
//					ev->Record2csv(callstack_);
//#endif
					//ev_callstack.append(modelTree->search(temp_iter)->key_value.FileName + ":" + callstack_);
					ev_callstack.append(callstack_);
					auto find_api = ransomapi_need_map.find(ev_callstack);
					if (find_api == ransomapi_need_map.end())
					{
//#ifdef ETW_EVENT_RECORD_TEST	
//						ev->Record2csv("find_api == ransomapi_need_map.end()");
//#endif
						if (m_umapRansomAPIIndexCache.size() < MAX_RANSOM_CACHE) {
							auto file_name = modelTree->search(temp_iter)->key_value.FileName;
							if (m_umapRansomDllCache.find(file_name) == m_umapRansomDllCache.end())
								m_umapRansomDllCache[file_name] = std::vector<ULONG64>();
							m_umapRansomDllCache[file_name].push_back(temp_iter);
							m_umapRansomAPIIndexCache[temp_iter] = -1;
						}
					}
					else
					{
						ev->m_bUseless = false;
						m_umapRansomAPIIndexCache[temp_iter] = find_api->second;
						auto file_name = modelTree->search(temp_iter)->key_value.FileName;
						if (m_umapRansomDllCache.find(file_name) == m_umapRansomDllCache.end())
							m_umapRansomDllCache[file_name] = std::vector<ULONG64>();
						m_umapRansomDllCache[file_name].push_back(temp_iter);
						CallstackUnit::increase(ev->get_process_id_(), find_api->second);
//#ifdef ETW_EVENT_RECORD_TEST	
//						std::string strTemp = to_string(ev->get_process_id_());
//						strTemp += "|";
//						strTemp += find_api->first;
//						strTemp += "|";
//						strTemp += to_string(find_api->second);
//						ev->Record2csv(strTemp);
//#endif
					}
				}
			}

		}

	} while (false);
}

// parse api by previous method, not implemented yet
/*
void EventRecordCallstack::ParseTopLevelAPIwithPrevious(EventRecordCallstack* ev)
{
}
*/

void EventRecordCallstack::ParseTopLevelAPIwithOptimize(EventRecordCallstack* ev)
{
	DWORD pid = ev->m_dwProcessId;
	auto &modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{		
		ev->m_bUseless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;
	bool flag = false;
	String& ev_callstack = ev->m_strCallstack;
	const auto& address_stack = ev->entry_address_vector_;

	int_32 iter = ev->kernel_start + 1;
	int_32 vector_size = ev->vector_size;
	for (; iter < vector_size; iter++)
	{
		if (flag)   // may be can add cache later for optimize
		{
			// do this operation because we find sometimes callstack:
			/*{"processID":3432,"threadID":3676,"TimeStamp":8172785732,"CallStack":"18446735277688847513(NOMODULE-SYSTEMMODULE),
			1962159625(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962159551(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962660486(\\Windows\\System32\\wow64.dll:Wow64SystemServiceEx),
			1962657438(\\Windows\\System32\\wow64.dll:Wow64LdrpInitialize),
			2001945539(\\Windows\\System32\\ntdll.dll:RtlImageDirectoryEntryToData),
			2002360192(\\Windows\\System32\\ntdll.dll:longjmp),
			2002007838(\\Windows\\System32\\ntdll.dll:LdrInitializeThunk),
			1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			5360515(\\Rats\\Dark Comet 5.3\\Dark Comet\\DarkComet.exe:NOAPI),
			......
			1967421578(\\Windows\\SysWOW64\\user32.dll:DispatchMessageW)"}*/

			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}
			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (strstr(search_module->key_value.FileName.c_str(), api_filename_mapping[ev_callstack].c_str()) == nullptr &&
				api_ntdll_need_set_win7.find(ev_callstack) == api_ntdll_need_set_win7.end())			
			//if (search_module->key_value.FileName.find(api_filename_mapping[ev_callstack]) == string::npos &&
			//	api_ntdll_need_set_win7.find(ev_callstack) == api_ntdll_need_set_win7.end())
			{
				//ev->useless = true;   // remove by zxw on 20200804
				return;
			}
			else
			{
				if (search_module->key_value.rva_tree == NULL)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				// can not get funcation name
				if (!search_function)
				{
					//callstack_ = "1";
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// next is still API we need, such as 
				//1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
				//1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState), 

				// find such as this:
				//8791757691994(\\Windows\\System32\\gdi32.dll:SelectObject)
				//8791757692022(\\Windows\\System32\\gdi32.dll:CreateCompatibleDC)
				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;
					continue;
				}
				else
				{
					//callstack_ = "1";
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}

		}
		else
		{
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call
            if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				continue;
			}
			// save address of system call we do not to parse 
			else if ((process_address_useless_cache[pid]).count(address_stack[iter]))
			{
				// not one we need
				ev->m_bUseless = true;
				return;
			}
			// save address of system call we need 
			else if ((process_API_address_cache[pid]).count(address_stack[iter]))
			{  //address of API we need
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];
				continue;
			}
			else if (APIaddress_keepon_cache[pid].count(address_stack[iter]))
			{
				ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);
			if (search_module)
			{
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					return;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win7.find(search_function->key_value.FileName) != api_ntdll_need_set_win7.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design
							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}
								if (process_address_cache.find((const unsigned long)address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}
										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
                                            // remove by zxw on 20200623 do not add "zw" in cache
											//process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win7.find(search_function->key_value.FileName) != api_keepon_set_win7.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
							}
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->m_bUseless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr || 
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)				
				{
					node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}
                }
                else if (strstr(search_module->key_value.FileName.c_str(), "kernel32.dll") != nullptr ||
                strstr(search_module->key_value.FileName.c_str(), "KernelBase.dll") != nullptr)
                {
                    node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
                    if (!search_function) {
                        process_address_useless_cache[pid].insert(address_stack[iter]);
                        ev->m_bUseless = true;
                        return;
                    }

                    if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end()) {
                        flag = true;
                        process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
                        ev_callstack = search_function->key_value.FileName;
                    }
                    else {
                       continue;
                    }
                }
				else
				{
					ev->m_bUseless = true;
					return;
				}
			}
			else
			{
				ev->m_bUseless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->m_bUseless = true;
	}
}

void EventRecordCallstack::ParseTopLevelAPIwithOptimizeWin10(EventRecordCallstack* ev)
{
	DWORD pid = ev->m_dwProcessId;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{
		ev->m_bUseless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;
	bool flag = false;
	String& ev_callstack = ev->m_strCallstack;
	const auto& address_stack = ev->entry_address_vector_;

	int iter = ev->kernel_start + 1;
	int vector_size = ev->vector_size;
	for (; iter < vector_size; iter++)
	{
		if (flag)   // may be can add cache later for optimize
		{
			// do this operation because we find sometimes callstack:
			/*{"processID":3432,"threadID":3676,"TimeStamp":8172785732,"CallStack":"18446735277688847513(NOMODULE-SYSTEMMODULE),
			1962159625(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962159551(\\Windows\\System32\\wow64cpu.dll:TurboDispatchJumpAddressEnd),
			1962660486(\\Windows\\System32\\wow64.dll:Wow64SystemServiceEx),
			1962657438(\\Windows\\System32\\wow64.dll:Wow64LdrpInitialize),
			2001945539(\\Windows\\System32\\ntdll.dll:RtlImageDirectoryEntryToData),
			2002360192(\\Windows\\System32\\ntdll.dll:longjmp),
			2002007838(\\Windows\\System32\\ntdll.dll:LdrInitializeThunk),
			1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
			5360515(\\Rats\\Dark Comet 5.3\\Dark Comet\\DarkComet.exe:NOAPI),
			......
			1967421578(\\Windows\\SysWOW64\\user32.dll:DispatchMessageW)"}*/

			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}

			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (search_module->key_value.rva_tree != NULL)
			{
				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				// can not get function name
				if (!search_function)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				// next is still API we need, such as 
				//1967466555(\\Windows\\SysWOW64\\user32.dll:GetKeyState),
				//1967466526(\\Windows\\SysWOW64\\user32.dll:GetKeyState), 

				// find such as this:
				//8791757691994(\\Windows\\System32\\gdi32.dll:SelectObject)
				//8791757692022(\\Windows\\System32\\gdi32.dll:CreateCompatibleDC)
				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;
					continue;
				}
				else
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}
			else
			{
				return;
			}
		}
		else
		{
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call
			if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				continue;
			}
			// save address of system call we do not to parse 
			else if (process_address_useless_cache[pid].find(address_stack[iter]) != process_address_useless_cache[pid].end())
			{
				// not one we need
				ev->m_bUseless = true;
				return;
			}
			// save address of system call we need 
			else if (process_API_address_cache[pid].find(address_stack[iter]) != process_API_address_cache[pid].end())
			{  //address of API we need
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];
				continue;
			}
			else if (APIaddress_keepon_cache[pid].find(address_stack[iter]) != APIaddress_keepon_cache[pid].end())
			{
				ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);
			if (search_module)
			{
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)				
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					continue;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)			
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win10.find(search_function->key_value.FileName) != api_ntdll_need_set_win10.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design

							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}

								if (process_address_cache.find((const unsigned long)address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										//std::cout << search_next_module->key_value.FileName << std::endl;
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}

										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
											process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win10.find(search_function->key_value.FileName) != api_keepon_set_win10.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{								
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrick(ev, iter + 1);
							}							
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->m_bUseless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}
                }
                else if (strstr(search_module->key_value.FileName.c_str(), "kernel32.dll") != nullptr ||
                strstr(search_module->key_value.FileName.c_str(), "KernelBase.dll") != nullptr) 
                {
                    node * search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
                    if (!search_function) {
                        process_address_useless_cache[pid].insert(address_stack[iter]);
                        ev->m_bUseless = true;
                        return;
                    }

                    if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end()) {
                        flag = true;
                        process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
                        ev_callstack = search_function->key_value.FileName;
                    }
                    else {
                        continue;
                    }
                }
				else
				{
					ev->m_bUseless = true;
					return;
				}
			}
			else
			{
				ev->m_bUseless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->m_bUseless = true;
	}
}

void EventRecordCallstack::ParseTopLevelAPIwithOptimizeWS2012R2(EventRecordCallstack* ev)
{
	DWORD pid = ev->m_dwProcessId;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{
		ev->m_bUseless = true;
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;
	bool flag = false;
	String& ev_callstack = ev->m_strCallstack;
	const auto& address_stack = ev->entry_address_vector_;

	int_32 iter = ev->kernel_start + 1;
	int_32 vector_size = ev->vector_size;
	for (; iter < vector_size; iter++)
	{
		if (flag)   // may be can add cache later for optimize
		{
			//next is exe address
			if (address_stack[iter] < exe_address_end_ && address_stack[iter] >= exe_address_base_)
			{
				return;
			}

			//next address is NO-MODULE
			node* search_module = modelTree->search(address_stack[iter]);
			if (!search_module)
			{
				return;
			}

			//next address in current process and module is not API we need in 
			if (search_module->key_value.rva_tree != NULL)
			{
				// get function next
				node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
				// can not get function name
				if (!search_function)
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;
				}

				if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
				{
					ev_callstack = search_function->key_value.FileName;
					continue;
				}
				else
				{
					//ev->useless = true;    // remove by zxw on 20200804
					return;  //next is not current API
				}
			}
			else
			{
				return;
			}
		}
		else
		{
			//save address such as Wow64LdrpInitialize.....always near with kernel and below actually func call
			if (process_address_cache[pid].find(address_stack[iter]) != process_address_cache[pid].end())
			{
				continue;
			}
			// save address of system call we do not to parse 
			else if (process_address_useless_cache[pid].find(address_stack[iter]) != process_address_useless_cache[pid].end())
			{
				// not one we need
				ev->m_bUseless = true;
				return;
			}
			// save address of system call we need 
			else if (process_API_address_cache[pid].find(address_stack[iter]) != process_API_address_cache[pid].end())
			{  //address of API we need
				flag = true;
				ev_callstack = process_API_address_cache[pid][address_stack[iter]];
				continue;
			}
			else if (APIaddress_keepon_cache[pid].find(address_stack[iter]) != APIaddress_keepon_cache[pid].end())
			{
				ParseTopLevelAPIwithRunqinTrickWS2012R2(ev, iter + 1);
				return;
			}

			node* search_module = modelTree->search(address_stack[iter]);
			if (search_module)
			{
				if (strstr(search_module->key_value.FileName.c_str(), "wow64win.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64cpu.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "wow64.dll") != nullptr)
				{
					process_address_cache[pid].insert(address_stack[iter]);
					continue;
				}

				if (search_module->key_value.rva_tree == NULL)
				{
					continue;
				}

				if (strstr(search_module->key_value.FileName.c_str(), "ntdll.dll") != nullptr)				
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (search_function != NULL)
					{
						if (search_function->key_value.FileName.substr(0, 2) != "Zw")
						{
							process_address_cache[pid].insert(address_stack[iter]);
							continue;
						}
						else if (api_ntdll_need_set_win10.find(search_function->key_value.FileName) != api_ntdll_need_set_win10.end())
						{
							// this two address is different 
							// so gamble, maybe need to change later
							// 2019.2.23: VanToM RAT 1.4 remoteshell is differnet from what we think before,
							// So need to change gamble policy

							//2019.2.27 find some bugs in previous version
							//recover gamble design

							if (iter != ev->kernel_start + 1)
							{   // so gamble, maybe need to change later
								flag = true;
								process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
								ev_callstack = search_function->key_value.FileName;
							}
							else
							{
								if (iter == vector_size - 1)  // last address
								{
									ev_callstack = search_function->key_value.FileName;
									return;
								}

								if (process_address_cache.find((const unsigned long)address_stack[iter + 1]) != process_address_cache.end())
								{
									continue;
								}
								else
								{
									node* search_next_module = modelTree->search(address_stack[iter + 1]);
									if (!search_next_module)
									{
										ev_callstack = search_function->key_value.FileName;
										return;
									}
									else if (search_next_module->key_value.rva_tree == NULL)
									{
										continue;
									}
									else
									{
										//std::cout << search_next_module->key_value.FileName << std::endl;
										node* search_next_func = (*(search_next_module->key_value.rva_tree)).search(address_stack[iter + 1] - search_next_module->key_value.ImageBase);
										if (!search_next_func)
										{
											process_address_cache[pid].insert(address_stack[iter]);
											continue;
										}

										if (api_need_set.find(search_next_func->key_value.FileName) != api_need_set.end())
										{
											flag = true;
                                            // remove by zxw on 20200623 do not add "zw" in cache
											//process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
											process_API_address_cache[pid][address_stack[iter + 1]] = search_next_func->key_value.FileName;
											ev_callstack = search_next_func->key_value.FileName;
											iter++;
										}
										else
										{
											process_address_cache[pid].insert(address_stack[iter]);
											process_address_cache[pid].insert(address_stack[iter + 1]);
											iter++;
											continue;
										}
									}
								}
							}
						}
						else if (api_keepon_set_win10.find(search_function->key_value.FileName) != api_keepon_set_win10.end())
						{  // no good way find,keep origin function
							// add by zxw on 20200210
							if (isKeeponParseAPI(ev, search_function->key_value.FileName, iter + 1))
							{
								APIaddress_keepon_cache[pid].insert(address_stack[iter]);
								ParseTopLevelAPIwithRunqinTrickWS2012R2(ev, iter + 1);
							}
							return;
						}
						else
						{
							// API we need do not in ntdll.dll, can use this condition to filter data
							process_address_useless_cache[pid].insert(address_stack[iter]);
							ev->m_bUseless = true;
							return;
						}
					}
				}
				else if (strstr(search_module->key_value.FileName.c_str(), "gdi32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "user32.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "win32u.dll") != nullptr ||
					strstr(search_module->key_value.FileName.c_str(), "gdi32full.dll") != nullptr)			
				{
					node* search_function = (*(search_module->key_value.rva_tree)).search(address_stack[iter] - search_module->key_value.ImageBase);
					if (!search_function)
					{
						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}

					if (api_need_set.find(search_function->key_value.FileName) != api_need_set.end())
					{
						flag = true;
						process_API_address_cache[pid][address_stack[iter]] = search_function->key_value.FileName;
						ev_callstack = search_function->key_value.FileName;
					}
					else
					{
						if (search_function->key_value.FileName == "GetClassNameW")
						{
							ULONG64 offset = address_stack[iter] - search_module->key_value.ImageBase - search_function->key_value.ImageBase;
							if (offset >= 0x6c && offset <= 0x83)
							{
								ev_callstack = "GetKeyState";
								return;
							}
						}

						process_address_useless_cache[pid].insert(address_stack[iter]);
						ev->m_bUseless = true;
						return;
					}
				}
				else
				{
					ev->m_bUseless = true;
					return;
				}
			}
			else
			{
				ev->m_bUseless = true;
				return;
			}
		}
	}

	if (iter != vector_size)
	{
		ev->m_bUseless = true;
	}
}

void EventRecordCallstack::ParseFullStackWithVector(EventRecordCallstack* ev)//real use
{
	std::string callstack_;
	DWORD pid = ev->m_dwProcessId;
	int N = 5;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (!modelTree || ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{
		ev->m_bUseless = true;
		return;
	}
	int  iter = 0;
	int length = ev->vector_size;
	if (length == 0) { return; }
	int n = length - 1 > N - 1 ? N - 1 : length - 1;

	const auto& address_stack = ev->entry_address_vector_;
	vector<int>& ev_vec_callstack = ev->m_vecCallstack;

	if (iter == length) return;

	unsigned long long exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	unsigned long long exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;

	for (; iter != length; iter++) {
		unsigned long long temp_iter = address_stack[iter];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_) {
			break;
		}
	}
	if (ev_vec_callstack.empty() && length) {
		while (--iter, iter >= 0 && n >= 0 && address_stack[iter] < 0xfffff00000000000) {
			unsigned long long temp_iter = address_stack[iter];
			callstack_ = ConvertAddress2APIName(ev, temp_iter);
			if (strstr(callstack_.c_str(), "NOOAPI") == nullptr && strstr(callstack_.c_str(), "NOMODULE") == nullptr && strstr(callstack_.c_str(), "NOAPI") == nullptr)
			{
				string temp = modelTree->search(temp_iter)->key_value.FileName;
				string temp2 = temp.substr(temp.find_last_of('\\') + 1);
				callstack_ = temp2 + ":" + callstack_;
				int now = PhfDetector::GetInstance().FindApiIndex(callstack_);
				if (now != -1 && now != ev->pre_api_index)
				{
					ev_vec_callstack.push_back(now);
					ev->pre_api_index = now;
				}
			}
		}
		if (PhfDetector::GetInstance().isUselessCallstack(ev_vec_callstack))
		{
			ev_vec_callstack.clear();
		}
	}
}

void EventRecordCallstack::ParseTopLevelAPIwithRunqinTrick(EventRecordCallstack* ev, int start_index /*= 0*/)
{
	int iter = start_index;
	int length = ev->vector_size;
	if (iter == length) return;

	DWORD pid = ev->m_dwProcessId;
	if (ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;

	String& ev_callstack = ev->m_strCallstack;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	if (modelTree)
	{
		for (iter = start_index; iter < length; iter++)
		{
			ULONG64 temp_iter = address_stack[iter];
			if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
			{
				break;
			}
			if (temp_iter >= 0xfffff00000000000)
			{
				continue;
			}

			node* search_module = modelTree->search(temp_iter);
			if (!search_module)
			{
				break;
			}

			if (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") != nullptr ||
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") != nullptr)
			{
				node* search_function = (*(search_module->key_value.rva_tree)).search(temp_iter - search_module->key_value.ImageBase);
				if (search_function)
				{
					ev_callstack = search_function->key_value.FileName;
					if (ev_callstack == "waveInOpen" || ev_callstack == "waveInAddBuffer")
					{
						return;
					}
				}
			}
		}
	}

	string temp_callstack_ = "";
	while (--iter, iter >= start_index)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < 0xfffff00000000000)
		{
			ev_callstack = std::move(ConvertAddress2APIName(ev, temp_iter));
			if (strstr(ev_callstack.c_str(), "NOOAPI") != nullptr ||
				strstr(ev_callstack.c_str(), "NOMODULE") != nullptr ||
				strstr(ev_callstack.c_str(), "NOAPI") != nullptr)			
			{
				continue;
			}
			else
			{
				break;
			}
		}
	}

	if (iter < 0) return;
}

void EventRecordCallstack::ParseTopLevelAPIwithRunqinTrickWS2012R2(EventRecordCallstack* ev, int_32 start_index /*= 0*/)
{
	int_32 iter = start_index;
	int_32 length = ev->vector_size;
	if (iter == length) return;

	DWORD pid = ev->m_dwProcessId;
	if (ObtainEntryAddress::m_umapExeNode.find(pid) == ObtainEntryAddress::m_umapExeNode.end())
	{
		return;
	}

	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;

	String& ev_callstack = ev->m_strCallstack;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	for (iter = start_index; iter < length; iter++)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			break;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || strstr(search_module->key_value.FileName.c_str(), "mciwave.dll") != nullptr)
			{
				break;
			}
			if (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") != nullptr ||
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") != nullptr)			
			{
				node* search_function = (*(search_module->key_value.rva_tree)).search(temp_iter - search_module->key_value.ImageBase);
				if (search_function)
				{
					ev_callstack = search_function->key_value.FileName;
					if (ev_callstack == "waveInOpen" || ev_callstack == "waveInAddBuffer")
					{
						return;
					}
				}
			}
		}
	}

	string temp_callstack_ = "";
	while (--iter, iter >= start_index)
	{
		ULONG64 temp_iter = address_stack[iter];
		if (temp_iter < 0xfffff00000000000)
		{
			ev_callstack = std::move(ConvertAddress2APIName(ev, temp_iter));
			if (strstr(ev_callstack.c_str(), "NOOAPI") != nullptr ||
				strstr(ev_callstack.c_str(), "NOMODULE") != nullptr ||
				strstr(ev_callstack.c_str(), "NOAPI") != nullptr)			
			{
				continue;
			}
			else
			{
				break;
			}
		}
	}

	if (iter < 0) return;
}

String EventRecordCallstack::ConvertAddress2APIName(EventRecordCallstack* ev, ULONG64 address)
{
	// convert address to api_name from here
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[ev->m_dwProcessId % Max_Process_ID];
	if (!modelTree)
	{
		return EMPTY_STRING;
	}

	String ret;
	node* search_module = modelTree->search(address);
	if (search_module != NULL)
	{
		//string module_name_result = search_module->key_value.FileName;
		if (!Setting::GetInstance().local_detector_parse())
			ret = search_module->key_value.FileName;

		// the dll is not load and parse successfully
		if (search_module->key_value.rva_tree == NULL)
		{
			ret.append(":NOAPI");
			//temp.clear();
		}
		else
		{
//#ifdef ETW_EVENT_RECORD_TEST	
//			ev->Record2csv(search_module->key_value.FileName);
//#endif
			node * search_function = (*(search_module->key_value.rva_tree)).search((address)-search_module->key_value.ImageBase);
			if (search_function != NULL)
			{
				if (InitCollector::GetCollector()->GetMode() == ONLINE_PARSE_MODE)
				{
					ret = search_function->key_value.FileName;

					//RUAN's computer,offset is GdipCreateSolidFill + 0x191db
					//To solve code suspend problem
					if (search_module->key_value.FileName.find("GdiPlus.dll") != String::npos)
					{
						ULONG64 offset = address - search_module->key_value.ImageBase - search_function->key_value.ImageBase;
						if (offset > 0x10000 && search_function->key_value.ImageEnd == INT_MAX)
						{
							ret = "GdipSaveImageToStream";
						}
					}
//#ifdef ETW_EVENT_RECORD_TEST	
//					ev->Record2csv(ret);
//#endif
				}
				else
				{
					String api_name_result = search_function->key_value.FileName;
					ret.append(":").append(api_name_result); // all parse successfully
//#ifdef ETW_EVENT_RECORD_TEST	
//					ev->Record2csv(api_name_result);
//#endif
				}
				/* check api and return string shorter than 9 */
			}
			else
			{
//#ifdef ETW_EVENT_RECORD_TEST	
//				ev->Record2csv(":NOOAPI");
//#endif
				ret.append(":NOOAPI"); // can't match any rva
				//temp.clear();
			}
		}
	}
	// can't find a module match the address(moduleBase < address < moduleEnd)
	else
	{
		if (address >= 0xfffff00000000000)
		{
			ret.append("NOMODULE-SYSTEMMODULE");
		}
		else
		{
			ret.append("NOMODULE");
		}
	}

	return ret;
}

bool EventRecordCallstack::isKeeponParseAPI(EventRecordCallstack * ev, String apiname, int_32 index)
{
	int_32 length = ev->vector_size;
	if (index >= length) return false;

	DWORD pid = ev->m_dwProcessId;
	const auto& address_stack = ev->entry_address_vector_;
	auto& modelTree = ObtainEntryAddress::m_moduleAddressTree[pid % Max_Process_ID];
	ULONG64 exe_address_base_ = ObtainEntryAddress::m_umapExeNode[pid].ImageBase;
	ULONG64 exe_address_end_ = ObtainEntryAddress::m_umapExeNode[pid].ImageEnd;
	if (strstr(apiname.c_str(), "ZwDeviceIoControlFile") != nullptr)
	{
		ULONG64 temp_iter = address_stack[index];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			return false;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || strstr(search_module->key_value.FileName.c_str(), "bcrypt.dll") == nullptr)
			{	// if next filename is not bcrypt.dll do not keep on parse
				return false;
			}
		}
	}
	else if (strstr(apiname.c_str(), "ZwWaitForSingleObject") != nullptr)
	{
		if (index + 3 >= length) return false;
		ULONG64 temp_iter = address_stack[index + 3];
		if (temp_iter < exe_address_end_ && temp_iter >= exe_address_base_)
		{
			return false;
		}
		if (temp_iter < 0xfffff00000000000 && modelTree)
		{
			node* search_module = modelTree->search(temp_iter);
			if (!search_module || (strstr(search_module->key_value.FileName.c_str(), "winmm.dll") == nullptr &&
				strstr(search_module->key_value.FileName.c_str(), "winmmbase.dll") == nullptr))
			{	// if next filename is not winmm.dll or winmmbase.dll do not keep on parse
				return false;
			}
		}
	}
	else
	{
		return true;
	}
	
	return true;
}
