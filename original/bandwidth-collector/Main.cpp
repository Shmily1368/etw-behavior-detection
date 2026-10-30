#include <tchar.h>
/********************************************************************
	Created:		2019-01-03
	Author:			chips;
	Version:		1.0.1(版本号);
	Description:	初始化项目;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/04/09 |	0.1.0	 |	zhenyuan	  | Create file
----------------------------------------------------------------------------
  2019/01/03 |	1.0.0	 |	chips		  | initLoggerRecord && initSetting && initCollector
----------------------------------------------------------------------------
*********************************************************************/
#pragma comment( lib, "Dbghelp.lib" )

#include "stdafx.h"
#include "setting.h"
#include "tool_functions.h"
#include "init_collector.h"
#include "init_collector_factory.h"
#include "obtain_entry_address.h"
#include "etw_configuration.h"
#include "task_queue_service.h"
#include <io.h>
#include <Windows.h>
#include <DbgHelp.h>
#include <chrono>
#include <queue>
#include <iomanip>
#define MaxDumpFileNum 4   //添加dump文件最大数量约束
RwLock dump_lock;
int dumpCount = 0;  
std::string dir;   //"dump"

using namespace std;

struct myTime {
	WORD wYear;
	WORD wMonth;
	WORD wDay;
	WORD wHour;
	WORD wMinute;
	WORD wSecond;
	myTime(WORD y, WORD m, WORD d, WORD h, WORD min, WORD s) :wYear(y), wMonth(m), wDay(d), wHour(h), wMinute(min), wSecond(s){}
	bool operator<(const myTime& a) const
	{
		if (wYear != a.wYear) return wYear > a.wYear;
		if (wMonth != a.wMonth) return wMonth > a.wMonth;
		if (wDay != a.wDay) return wDay > a.wDay;
		if (wHour != a.wHour) return wHour > a.wHour;
		if (wMinute != a.wMinute) return wMinute > a.wMinute;
		if (wSecond != a.wSecond) return wSecond > a.wSecond;
	}
};

priority_queue<myTime> timequeue;

void DumpFileCount()        //程序启动后当前所含的dump文件数
{
	WCHAR current_path[MAX_PATH] = { 0 };
	GetCurrentDirectory(sizeof(current_path), current_path);

	std::wstring dump_dir = std::wstring(current_path) + _T("\\*");
	dir = "dump";
	_finddata64i32_t dir_data;
	auto hdir = _findfirst(ToolFunctions::WStringToString(dump_dir).c_str(), &dir_data);
	bool exist_flag = false;
	if (hdir != -1)
	{
		while (_findnext(hdir, &dir_data) == 0)
		{
			if (dir_data.attrib == _A_SUBDIR)
			{
				if (dir_data.name != NULL) {
					string dirname(dir_data.name);
					string temp_dir = dirname;
					transform(temp_dir.begin(), temp_dir.end(), temp_dir.begin(), ::tolower);
					if (temp_dir == dir) {
						dir = dirname;
						exist_flag = true;
						break;
					}
				}
			}
		}
	}
	wstring dir_now = std::wstring(current_path) + _T("\\") + ToolFunctions::StringToWString(dir);
	if (!exist_flag) {
		CreateDirectory(dir_now.c_str(),NULL);
	}
	std::wstring dump_file_path = std::wstring(current_path) + _T("\\") +ToolFunctions::StringToWString(dir) +_T("\\*");   
	_finddata64i32_t file_data;
	string dumpsuffix = ".dmp";
	string dumpprefix = "collector_";
	int dumplength = dumpsuffix.length();
	int prefixlength = dumpprefix.length();
	auto hfile = _findfirst(ToolFunctions::WStringToString(dump_file_path).c_str(), &file_data);
	if(hfile != -1)
	{
		while (_findnext(hfile, &file_data) == 0)
		{
			if (file_data.attrib != _A_SUBDIR)
			{
				if (file_data.name != NULL) {
					string filename(file_data.name);
					int filelength = filename.length();
					if (filelength > prefixlength + dumplength) {
						if (filename.substr(filelength - dumplength) == dumpsuffix) {
							WORD y=0,m=0,d=0,h=0,min=0,s=0;
							dumpCount++;
							string data_temp = filename.substr(prefixlength, filelength - dumplength - prefixlength);
							sscanf_s(data_temp.c_str(), "%04hd-%02hd-%02hd %02hd-%02hd-%02hd", &y, &m, &d, &h, &min, &s);
							myTime temp(y, m, d, h, min, s);
							timequeue.push(temp);
						}
					}
				}
			}
			
		}
	}

}

void DumpFileClean()
{
	int clean_num = MaxDumpFileNum - dumpCount +1;
	WCHAR current_path[MAX_PATH] = { 0 };
	GetCurrentDirectory(sizeof(current_path), current_path);
	wstring path(current_path);
	string dump_file_dir = ToolFunctions::WStringToString(path);
	for (int i = 0; i < clean_num; i++) {

		if (!timequeue.empty())
		{
			myTime a = timequeue.top();
			timequeue.pop();
			char data_temp[50];
			sprintf_s(data_temp, "%04hd-%02hd-%02hd %02hd-%02hd-%02hd", a.wYear, a.wMonth, a.wDay, a.wHour, a.wMinute, a.wSecond);
			string data(data_temp);
			string dump_file_path = dump_file_dir + "\\" + dir + "\\collector_" + data + ".dmp";
			remove(dump_file_path.c_str());
			dumpCount--;
		}		
	}

}

void DumpMiniDump(HANDLE dump_handle, PEXCEPTION_POINTERS exception_p)
{
    if (exception_p == NULL) //如果没有传入异常, 比如是在程序里面调用的, 生成一个异常
    {
        // Generate exception to get proper context in dump
        __try {
            OutputDebugString(_T("raising exception\r\n"));
            RaiseException(EXCEPTION_BREAKPOINT, 0, 0, NULL);
        }
        __except (DumpMiniDump(dump_handle, GetExceptionInformation()),
            EXCEPTION_CONTINUE_EXECUTION) {
        }
    }
    else {
        // Dump信息  
        MINIDUMP_EXCEPTION_INFORMATION dump_info;
        dump_info.ExceptionPointers = exception_p;
        dump_info.ThreadId = GetCurrentThreadId();
        dump_info.ClientPointers = TRUE;

        // 写入Dump文件内容  
        MINIDUMP_TYPE dump_type = MiniDumpNormal;
        if (Setting::GetInstance().enable_maximum_dump()) {
            dump_type = (MINIDUMP_TYPE)(MiniDumpWithFullMemory | MiniDumpWithFullMemoryInfo | MiniDumpWithHandleData | MiniDumpWithThreadInfo);
        }
        MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), dump_handle, dump_type, &dump_info, NULL, NULL);
    }
}

void CreateDumpFile(LPCWSTR dump_file_path, EXCEPTION_POINTERS* exception_p)
{
	// 创建Dump文件  
	HANDLE dump_handle = CreateFile(dump_file_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (dump_handle == INVALID_HANDLE_VALUE) return ;

    DumpMiniDump(dump_handle, exception_p);

	CloseHandle(dump_handle);
}

LONG CrashHandler(EXCEPTION_POINTERS *pException) 
{
	// add by zxw on 20191107 添加空指针保护
	dump_lock.WriteLock();
	if (InitCollector::GetCollector())
		InitCollector::GetCollector()->StopETWSession();

	WCHAR current_path[MAX_PATH] = { 0 };
	GetCurrentDirectory(sizeof(current_path), current_path);
	if (dumpCount >= MaxDumpFileNum)
	{
		DumpFileClean();
	}
	wstring time_now = ToolFunctions::GetPresentTime();
	LoggerRecord::WriteLog(L"CrashHandler: generate dump file, time: " + time_now, LogLevel::INFO);
	WORD y = 0, m = 0, d = 0, h = 0, min = 0, s = 0;
	dumpCount++;
	sscanf_s(ToolFunctions::WStringToString(time_now).c_str(), "%04hd-%02hd-%02hd %02hd-%02hd-%02hd", &y, &m, &d, &h, &min, &s);
	myTime temp(y, m, d, h, min, s);
	timequeue.push(temp);
	std::wstring dump_file_path = std::wstring(current_path) + _T("\\") + ToolFunctions::StringToWString(dir) + _T("\\collector_") + time_now + _T(".dmp");
	CreateDumpFile(dump_file_path.data(), pException);
	dump_lock.WriteUnlock();
	Sleep(1000);     //避免时间相同，否则会只保留一个记录
	return EXCEPTION_EXECUTE_HANDLER;
}

int main(int argc, char *argv[]) 
{
    auto modulePath = ToolFunctions::GetModuleDirectory();
    if (SetCurrentDirectory(modulePath.c_str()))
    {
        std::wcout << ToolFunctions::GetPresentTime() << L": SetCurrentDirectory " << modulePath << std::endl;
    }
    
	//init log
	std::wcout << ToolFunctions::GetPresentTime() << L": init logger" << std::endl;   
	LoggerRecord::InitLoggerRecord();

	//init setting;
	std::wcout << ToolFunctions::GetPresentTime() << L": init setting" << std::endl;
	Setting::GetInstance().Init(argc, argv);

	//init task queue service;
	std::wcout << ToolFunctions::GetPresentTime() << L": init task queue service" << std::endl;
	TaskQueueService::GetInstance().Start();

	//add error handle for debug, will delete it when release;
	DumpFileCount();
	std::wcout << ToolFunctions::GetPresentTime() << L": init crash handler" << std::endl;
	SetUnhandledExceptionFilter((LPTOP_LEVEL_EXCEPTION_FILTER)CrashHandler);

	//init collector
	std::wcout << ToolFunctions::GetPresentTime() << L": init collector" << std::endl;
	InitCollectorFactory factory;
	factory.Create();

	if (InitCollector::GetCollector())
	{
		//collector action
		InitCollector::GetCollector()->Init();
        // add by zxw on 20200724 start one sec later waite init over
        Sleep(1000);
		InitCollector::GetCollector()->Excute();
		InitCollector::GetCollector()->Clean();
	}
	else 
	{
		//LoggerRecord::WriteLog(L"init fail, setting mode is " + Setting::GetInstance().GetChar("mode"), INFO);
		LoggerRecord::WriteLog(L"init fail, setting mode = " + Setting::GetInstance().collector_mode(), LogLevel::ERR);
	}

	factory.Recycle();

	TaskQueueService::GetInstance().Stop();
	getchar();
	return 0;
}
