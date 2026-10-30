#include "stdafx.h"
#include "thread_task_monitor.h"
#include "global_enum_def.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "obtain_entry_address.h"
#include "certificate_tool.h"
#include "tool_functions.h"
#include "event_record_pruner.h"
#include "filter.h"

#include <windows.h> 
#include <wbemidl.h> 
#include <psapi.h>


void MemoryMonitor()
{
	
}


void MonitorThreadTask::_Excute()
{
    // add by zxw on 20191225
//     Sleep(MS_ONE_SECOND);
//     SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
    bool isFirst = true;
	uint_32 counter = 0;
	while (!_stop_flag)
	{
		++counter;
		if (counter % 10 == 0)
		{
			//counter = 0;

			_DataCacheMonitor();
			_ProcessMemoryMonitor();
#ifdef OBJECT_MEMORY_MONITOR
			_MemoryLeakMonitor();
#endif
		}
        // add by zxw on 20200821
        if (counter % 100 == 0) // every 100 s 
        {           
            if (isFirst)
            {
                isFirst = false;
                SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
                WriteLog4cPlus(INFO_LEVEL, L"first start SetProcessWorkingSetSize Process Mem WorkingSetSize: %d MB PagefileUsage: %d MB", _mem_WorkingSetSize, _mem_PagefileUsage);
            }
        }
        // add by zxw on 20191225 SetProcessWorkingSetSize
        if (counter % 1000 == 0) // every 1000 s 
        {
            counter = 0;
            if (_mem_WorkingSetSize > MAX_MEM_SET_SIZE) // mem > 120MB
            {                
                SetProcessWorkingSetSize(GetCurrentProcess(), -1, -1);
                WriteLog4cPlus(INFO_LEVEL, L"SetProcessWorkingSetSize Process Mem WorkingSetSize: %d MB PagefileUsage: %d MB ",_mem_WorkingSetSize, _mem_PagefileUsage);
            }
        }
        //
		Sleep(MS_ONE_SECOND);
	}
}

void MonitorThreadTask::_ProcessMemoryMonitor()
{
    int_32 mem_pagefileusage = 0;
    int_32 mem_workingsetsize = 0;
    SYSTEM_INFO si;
    GetSystemInfo(&si);

    OSVERSIONINFO osvi;
    memset(&osvi, 0, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);
    GetVersionEx(&osvi);


    HANDLE handle = GetCurrentProcess();
    if (handle)
    {          
        PROCESS_MEMORY_COUNTERS_EX procCnt = { 0 };
        if (GetProcessMemoryInfo(handle, (PPROCESS_MEMORY_COUNTERS)&procCnt, sizeof(procCnt)))
        {
            mem_workingsetsize = procCnt.WorkingSetSize * 1.0f / 1048576;
            mem_pagefileusage = (int_32)(procCnt.PagefileUsage / (1024 * 1024));
        }
        else
            WriteLog4cPlus(ERROR_LEVEL, L"GetProcessMemoryInfo error in get process Mem, errcode = %d", GetLastError());
       
        if (osvi.dwMajorVersion >= 6)
        {
            PSAPI_WORKING_SET_INFORMATION workSet;
            memset(&workSet, 0, sizeof(workSet));
            BOOL bRet = QueryWorkingSet(handle, &workSet, sizeof(workSet));
            if (bRet || (!bRet && GetLastError() == ERROR_BAD_LENGTH))
            {
                int nSize = sizeof(workSet.NumberOfEntries) + workSet.NumberOfEntries * sizeof(workSet.WorkingSetInfo);
                char* pBuf = new char[nSize];
                if (pBuf)
                {
                    QueryWorkingSet(handle, pBuf, nSize);
                    PSAPI_WORKING_SET_BLOCK* pFirst = (PSAPI_WORKING_SET_BLOCK*)(pBuf + sizeof(workSet.NumberOfEntries));
                    INT64 dwMem = 0;
                    for (ULONG_PTR nMemEntryCnt = 0; nMemEntryCnt < workSet.NumberOfEntries; nMemEntryCnt++, pFirst++)
                    {
                        if (pFirst->Shared == 0) dwMem += si.dwPageSize;
                    }
                    delete[] pBuf;
                    pBuf = NULL;

                    if (workSet.NumberOfEntries > 0)
                    {
                        mem_workingsetsize = dwMem / 1048576;
                    }
                }
            }
            else
            {
                WriteLog4cPlus(ERROR_LEVEL, L"error in get process Mem, errcode = %d", GetLastError());
            }
        }
        CloseHandle(handle);
    }
    else
    {
        WriteLog4cPlus(ERROR_LEVEL, L"error in get process Mem GetCurrentProcess failed, errcode = %d", GetLastError());
    }
    _mem_WorkingSetSize = mem_workingsetsize;
    _mem_PagefileUsage = mem_pagefileusage;
}

void MonitorThreadTask::_DataCacheMonitor()
{
	size_t wait_send_num;
	if (InitCollector::GetCollector())
		wait_send_num = InitCollector::GetCollector()->WaitSendDataSize();
#ifdef OUTPUT_COMMAND_LINE       
	cout << "DebugThread::wait_send_dataqueue size: " << wait_send_num << endl;
#endif // OUTPUT_COMMAND_LINE;
// 	size_t wait_parse_count = InitCollector::wait_parse_event_queue.size_approx();
// 	cout << "DebugThread::wait_parse_event_queue size: " << wait_parse_count << endl;

	WriteLog4cPlus(DEBUG_LEVEL, L"DebugThread: wait_send_dataqueue:  %d", wait_send_num);
//	WriteLog4cPlus(DEBUG_LEVEL, L"DebugThread: wait_parse_event_queue:  %d", wait_parse_count);

	WriteLog4cPlus(DEBUG_LEVEL, L"FileKeyMap:  %d", EventRecordFileio::file_key2file_info_map.size());
	WriteLog4cPlus(DEBUG_LEVEL, L"FileObjectMap:  %d", EventRecordFileio::file_object2file_info_map.size());
	WriteLog4cPlus(DEBUG_LEVEL, L"FileRenameMap:  %d", EventRecordFileio::fileiorename_cache_map.size());

	WriteLog4cPlus(DEBUG_LEVEL, L"Certificate_map:  %d", CertificateTool::CertificateCacheSize());

	WriteLog4cPlus(DEBUG_LEVEL, L"ObtainEntryAddress: DLLmodualTree count =  %d", ObtainEntryAddress::m_umapDLLmodual2Tree.size());
	WriteLog4cPlus(DEBUG_LEVEL, L"ObtainEntryAddress: exe_node_map count =  %d", ObtainEntryAddress::m_umapExeNode.size());
	WriteLog4cPlus(DEBUG_LEVEL, L"ObtainEntryAddress: module_btree_map count =  %d", ObtainEntryAddress::m_umapModuleName2Btree.size());

    // registry cache
    WriteLog4cPlus(DEBUG_LEVEL, L"EventRecordRegistry::key_handle2key_name_map:  %d", EventRecordRegistry::key_handle2key_name_map.size());
    WriteLog4cPlus(DEBUG_LEVEL, L"EventRecordRegistry::thread2_keyname:  %d", EventRecordRegistry::thread2_keyname.size()); 

	EventRecordPruner::GetInstance().LogCacheSize();

    // add by zxw on 20200812
    Filter::GetInstance().LogCacheSize();

}

MonitorThreadTask::MonitorThreadTask()
	: BaseThreadTask(MONITOR_TASK_MODE)
{
	
}

MonitorThreadTask::~MonitorThreadTask()
{

}

void MonitorThreadTask::Log()
{

}

void MonitorThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitMonitorThreadTask");
#ifdef OUTPUT_COMMAND_LINE       
	cout << "InitMonitorThreadTask" << endl;
#endif // OUTPUT_COMMAND_LINE;
}

#ifdef OBJECT_MEMORY_MONITOR

void MonitorThreadTask::_MemoryLeakMonitor()
{
	AutoLock lock(m_lock);

	for (auto i : m_mapObjectName2Info)
	{
		std::wstring temp = L"MonitorThreadTask::_MemoryLeakMonitor: object is " + ToolFunctions::StringToWString(i.first) \
			+ L" ,construction_num = " + std::to_wstring(i.second.construction_num) \
			+ L" ,destructor_num = " + std::to_wstring(i.second.destructor_num);
		WriteLog4cPlus(INFO_LEVEL, temp);
		std::wcout << temp << endl;
	}
}

void MonitorThreadTask::AddObjectInfo(EM_MonitorObjectInfoType type, const string& object_name)
{
	AutoLock lock(m_lock);

	if (m_mapObjectName2Info.find(object_name) != m_mapObjectName2Info.end())
	{
		ObjectInfo& object_info = m_mapObjectName2Info[object_name];
		if (type == EM_MonitorObjectInfoType::CONSTRUCTION_TYPE)
		{
			object_info.construction_num++;
		}
		else
		{
			object_info.destructor_num++;
		}
	}
	else
	{
		ObjectInfo object_info;
		object_info.construction_num = 1;
		m_mapObjectName2Info[object_name] = object_info;
	}
}

#endif

