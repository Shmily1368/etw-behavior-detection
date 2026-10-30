#include "stdafx.h"
#include "etw_configuration.h"

#include <windows.h>
#include <wbemidl.h>
#include <wmistr.h>
#include <evntrace.h>
#include <time.h>
#include <tdh.h> //PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
#include <in6addr.h>
#include <conio.h>
#include <strsafe.h>

#include <fstream>
#include <sstream>
#include <stdio.h>

#include "setting.h"
#include "tool_functions.h"

using namespace std;

std::set<int> ETWConfiguration::m_setEnableStackEvents;
bool g_exit = false; //whether exit for offline collect Mode

ETWConfiguration::ETWConfiguration()
{
	if (ToolFunctions::IsOldOs()) {
		m_wcsSessionName = KERNEL_LOGGER_NAME;
	}
	else {
		m_wcsSessionName = L"MSEtwDataCollector";
	}
	Preemption();
	Sleep(2000);
	m_bLowMode = false;

	do 
	{
		if (!Setting::GetInstance().enable_hardware_adjustment())	break;

		String cpu_name;
		if (!ToolFunctions::GetCpuName(cpu_name) || cpu_name.find("Intel") == String::npos)
		{
			break;
		}

		STRING_VECTOR cpu_info;
		StringUtil::split(cpu_name, ' ', cpu_info);
		if (cpu_info.size() < 3)
		{
			break;
		}

		String cpu_model = StringUtil::ToLowerCase(cpu_info[2]);
		if (!StringUtil::IsStartWith(cpu_model, "i", true))
		{
			break;
		}

		if (cpu_model.find("m") != String::npos)
		{
			m_bLowMode = true;
			break;
		}

		if (StringUtil::IsStartWith(cpu_model, "i3", true))
		{
			m_bLowMode = true;
			break;
		}

		if (StringUtil::IsStartWith(cpu_model, "i5", true) && (cpu_model.find("u") != String::npos))
		{
			m_bLowMode = true;
			break;
		}

	} while (0);

	WriteLog4cPlus(WARN_LEVEL, L"ETWConfiguration::ETWConfiguration: low_mode = %d", m_bLowMode);

    // mod by zxw on20200415 honey pot open registry
    if (Setting::GetInstance().enable_honey_pot())
    {
        m_ulEnableFlag = 0
            | EVENT_TRACE_FLAG_CSWITCH          // context switches
            | EVENT_TRACE_FLAG_IMAGE_LOAD		// image load
            | EVENT_TRACE_FLAG_FILE_IO_INIT
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_DISK_FILE_IO     // requires disk IO
            | EVENT_TRACE_FLAG_DISK_IO
            //| EVENT_TRACE_FLAG_FILE_IO          // file IO
            | EVENT_TRACE_FLAG_PROCESS			// process start & end
            | EVENT_TRACE_FLAG_THREAD			// thread start & end

            //local detector lcs dont need
            | EVENT_TRACE_FLAG_REGISTRY         // registry calls
            //| EVENT_TRACE_FLAG_ALPC             // ALPC traces
            //| EVENT_TRACE_FLAG_DISK_IO          // physical disk IO
            //| EVENT_TRACE_FLAG_DISK_IO_INIT     // physical disk IO initiation
            ;
    }
    else
    {
        m_ulEnableFlag = 0
            | EVENT_TRACE_FLAG_CSWITCH          // context switches
            | EVENT_TRACE_FLAG_IMAGE_LOAD		// image load
            | EVENT_TRACE_FLAG_FILE_IO_INIT
            | EVENT_TRACE_FLAG_NETWORK_TCPIP
            | EVENT_TRACE_FLAG_DISK_FILE_IO     // requires disk IO
            | EVENT_TRACE_FLAG_DISK_IO
            //| EVENT_TRACE_FLAG_FILE_IO          // file IO
            | EVENT_TRACE_FLAG_PROCESS			// process start & end
            | EVENT_TRACE_FLAG_THREAD			// thread start & end

            //local detector lcs dont need
            //| EVENT_TRACE_FLAG_REGISTRY         // registry calls
            //| EVENT_TRACE_FLAG_ALPC             // ALPC traces
            //| EVENT_TRACE_FLAG_DISK_IO          // physical disk IO
            //| EVENT_TRACE_FLAG_DISK_IO_INIT     // physical disk IO initiation
            ;
    }

	if (Setting::GetInstance().enable_ransom_detector())
	{
		m_ulEnableFlag |= EVENT_TRACE_FLAG_REGISTRY;   // registry
	}

	if (!m_bLowMode)	
		m_ulEnableFlag |= EVENT_TRACE_FLAG_SYSTEMCALL;       // system calls

	//string temp = Setting::GetInstance().GetString("offline_log_file");
	m_strLogfilePath = ToolFunctions::StringToWString(Setting::GetInstance().offline_log_file());
}

ETWConfiguration::~ETWConfiguration()
{
	Preemption();
}


bool ctrlHandler(DWORD dCtrlType)
{
	switch (dCtrlType)
	{
	case CTRL_C_EVENT:
		g_exit = true;
		return false;

	default:
		return false;
	}
}

void ETWConfiguration::SetTraceProperties(EVENT_TRACE_PROPERTIES * pSessionProperties, ULONG BufferSize, bool is_real_time)
{
    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1; //QPC clock resolution
                                                 //	pSessionProperties->Wnode.Guid = SystemTraceControlGuid;
    pSessionProperties->EnableFlags = m_ulEnableFlag;

    if (is_real_time)
    {
        pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        pSessionProperties->LogFileNameOffset = 0;
    }
    else
    {
        pSessionProperties->LogFileMode = EVENT_TRACE_FILE_MODE_SEQUENTIAL | EVENT_TRACE_SYSTEM_LOGGER_MODE;
        pSessionProperties->LoggerNameOffset = sizeof(EVENT_TRACE_PROPERTIES);
        pSessionProperties->LogFileNameOffset = sizeof(EVENT_TRACE_PROPERTIES) + (size(m_wcsSessionName) + 1) * sizeof(WCHAR);
        StringCbCopy((LPWSTR)((char*)pSessionProperties + pSessionProperties->LogFileNameOffset), (m_strLogfilePath.length() + 1) * 2, m_strLogfilePath.c_str());
    }
    pSessionProperties->MaximumBuffers = 128;
    pSessionProperties->BufferSize = 512;
}

int ETWConfiguration::ConfigureEtwSession(bool is_real_time, void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	ULONG status = ERROR_SUCCESS;
	TRACEHANDLE SessionHandle = 0;
	EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
	ULONG BufferSize = 0;

	// Allocate memory for the session properties. The memory must
	// be large enough to include the log file name and session name,
	// which get appended to the end of the session properties structure.

	BufferSize = sizeof(EVENT_TRACE_PROPERTIES)
		+ (size(m_wcsSessionName) + 1) * sizeof(WCHAR);

	if (!is_real_time) 
	{
		BufferSize += (ULONG)((m_strLogfilePath.length() + 1) * 2);
	}

	pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
	if (NULL == pSessionProperties)
	{
		wprintf(L"Unable to allocate %d bytes for properties structure.\n", BufferSize);
		return -1;
	}

	// Set the session properties. You only append the log file name
	// to the properties structure; the StartTrace function appends
	// the session name for you.
    SetTraceProperties(pSessionProperties, BufferSize, is_real_time);
	// Create the trace session.

	status = StartTrace((PTRACEHANDLE)&SessionHandle, m_wcsSessionName.c_str(), pSessionProperties);

	if (ERROR_SUCCESS != status)
	{
		if (ERROR_ALREADY_EXISTS == status)
		{
            status = ::ControlTrace((TRACEHANDLE)NULL, m_wcsSessionName.c_str(), pSessionProperties
				, EVENT_TRACE_CONTROL_STOP);
			StopEtwSession();
			//Preemption();
			Sleep(10000);
            if (SUCCEEDED(status))
            {
                SetTraceProperties(pSessionProperties, BufferSize, is_real_time);
                status = ::StartTrace((PTRACEHANDLE)&SessionHandle, m_wcsSessionName.c_str(), pSessionProperties);
                if (ERROR_SUCCESS != status)
                {
                    WriteLog4cPlus(ERROR_LEVEL, L"ETWConfiguration::ConfigureEtwSession StartTrace failed, err = %d", status);
                    return -1;
                }
            }
            else
            {
                WriteLog4cPlus(ERROR_LEVEL, L"ETWConfiguration::ConfigureEtwSession ControlTrace failed, err = %d", status);
                return -1;
            }
		}
		else
		{
            WriteLog4cPlus(ERROR_LEVEL, L"ETWConfiguration::ConfigureEtwSession StartTrace failed, status err = %d", status);
            wprintf(L"EnableTrace() failed with %lu\n", status);
            return -1;
		}
	}


	m_thSessionHandle = SessionHandle;
	m_pSessionProperties = pSessionProperties;

	if (m_vctEnableStackEvents.size() != 0) 
	{
		SetupEventStackwalk();
	}
#ifdef ETW_DELAY_EXIT_AND_RECORD_TRACE_INFO
	std::thread thrDelay([&]()
		{
			Sleep(5 * 60 * 1000);
			::StopTrace((TRACEHANDLE)SessionHandle, m_wcsSessionName.c_str(), pSessionProperties);
		});
	thrDelay.detach();
#endif // ETW_DELAY_EXIT_AND_RECORD_TRACE_INFO

	if (is_real_time) 
	{
		SetupEventConsumer(consum_event_realtime);
	}
	else 
	{
		//add by jiehao.meng 2018/10/24 ctrl+c to exit; for offline collect mode 
		SetConsoleCtrlHandler((PHANDLER_ROUTINE)ctrlHandler, true);
		while (!g_exit)
		{
			Sleep(10);
		}
	}

	WriteLog4cPlus(ERROR_LEVEL, L"ETWConfiguration::ConfigureEtwSession End Info NumberOfBuffers:%ld FreeBuffers:%ld EventsLost:%ld BuffersWritten:%ld LogBuffersLost:%ld RealTimeBuffersLost:%ld"
		, pSessionProperties->NumberOfBuffers
		, pSessionProperties->FreeBuffers
		, pSessionProperties->EventsLost
		, pSessionProperties->BuffersWritten
		, pSessionProperties->LogBuffersLost
		, pSessionProperties->RealTimeBuffersLost);
	return 0;

}

ULONG ETWConfiguration::StopEtwSession()
{
	if (m_thSessionHandle != 0 && m_pSessionProperties != NULL)
	{
		return StopTrace(m_thSessionHandle, m_wcsSessionName.c_str(), m_pSessionProperties);
	}
	
	return ERROR_SUCCESS;
}

void ETWConfiguration::SetupEventConsumer(void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	EVENT_TRACE_LOGFILE event_logfile;
	TRACE_LOGFILE_HEADER* event_logfile_header;
	TRACEHANDLE event_logfile_handle;
	BOOL event_usermode = FALSE;


	event_logfile_header = &event_logfile.LogfileHeader;
	ZeroMemory(&event_logfile, sizeof(EVENT_TRACE_LOGFILE));
	event_logfile.LoggerName = (LPWSTR)m_wcsSessionName.c_str();

	// consum_event() is the callback function. should be writed in this class.
	// If everything go well, the program will be block here.
	event_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event_realtime);

	event_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
	event_logfile_handle = OpenTrace(&event_logfile);
	if (INVALID_PROCESSTRACE_HANDLE == event_logfile_handle)
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
	}

	event_usermode = event_logfile_header->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;
	if (event_logfile_header->PointerSize != sizeof(PVOID))
	{
		event_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)event_logfile_header +
			2 * (event_logfile_header->PointerSize - sizeof(PVOID)));
	}
    // add by zxw on 20201229
    auto eventmonitor_worker = std::thread(std::bind(&ETWConfiguration::_EventMonitorExec, this));
    eventmonitor_worker.detach();
    //
	TDHSTATUS temp_status = ProcessTrace(&event_logfile_handle, 1, 0, 0);
	if (temp_status != ERROR_SUCCESS && temp_status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", temp_status);
		goto cleanup;
	}

cleanup:
	if (INVALID_PROCESSTRACE_HANDLE != event_logfile_handle)
	{
		temp_status = CloseTrace(event_logfile_handle);
	}
}

inline void ETWConfiguration::SetupEventStackwalk()
{
	TRACE_INFO_CLASS information_class = TraceStackTracingInfo;
	TraceSetInformation(m_thSessionHandle, information_class, &m_vctEnableStackEvents[0], (ULONG)(m_vctEnableStackEvents.size() * sizeof(CLASSIC_EVENT_ID)));
	return;
}

void ETWConfiguration::SetEnableStackEvents(std::vector<CLASSIC_EVENT_ID> enable_stack_events)
{
	if (m_bLowMode)	return;

	m_vctEnableStackEvents = enable_stack_events;
	for (auto iter = enable_stack_events.begin(); iter != enable_stack_events.end(); iter++)
	{
		m_setEnableStackEvents.insert(iter->EventGuid.Data1 + iter->Type);
	}
}

void ETWConfiguration::_EventMonitorExec() 
{
    EVENT_TRACE_PROPERTIES* pSessionProperties = NULL;
    ULONG BufferSize = 0;

    BufferSize = sizeof(EVENT_TRACE_PROPERTIES)
        + (size(m_wcsSessionName) + 1) * sizeof(WCHAR);

    pSessionProperties = (EVENT_TRACE_PROPERTIES*)malloc(BufferSize);
    if (NULL == pSessionProperties) {
        WriteLog4cPlus(ERROR_LEVEL, L"Unable to allocate bytes for properties structure. size: %d", BufferSize);    
        return;
    }
    SetTraceProperties(pSessionProperties, BufferSize, true);
    while (true) {
        Sleep(10000);
        auto status = ::ControlTrace((TRACEHANDLE)NULL, m_wcsSessionName.c_str(), pSessionProperties
			, EVENT_TRACE_CONTROL_QUERY);
        if (ERROR_SUCCESS == status) {
            if (pSessionProperties->EnableFlags != m_ulEnableFlag)
            {
                WriteLog4cPlus(WARN_LEVEL, L"EnableFlags is changed: %llu", pSessionProperties->EnableFlags);
                StopEtwSession();
                break;
            }
        }
        Sleep(10000);
    }   
}

void ETWConfiguration::ConsumeLogFile(void __stdcall consum_event_realtime(PEVENT_RECORD))
{
	TDHSTATUS status = ERROR_SUCCESS;
	EVENT_TRACE_LOGFILE trace;
	TRACE_LOGFILE_HEADER* pHeader = &trace.LogfileHeader;
	TRACEHANDLE g_hTrace;
	BOOL g_bUserMode = FALSE;

	// Identify the log file from which you want to consume events
	// and the callbacks used to process the events and buffers.
	ZeroMemory(&trace, sizeof(EVENT_TRACE_LOGFILE));

	//consume data from logfile
	trace.LogFileName = (LPWSTR)m_strLogfilePath.c_str();
	wcout << (LPWSTR)m_strLogfilePath.c_str() << endl;
	trace.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(consum_event_realtime);
	trace.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;


	g_hTrace = OpenTrace(&trace);
	if (INVALID_PROCESSTRACE_HANDLE == g_hTrace)//打开失败一般为打不开这个.bin文件，没有test.bin或者没有管理员权限
	{
		wprintf(L"OpenTrace failed with %lu\n", GetLastError());
		goto cleanup;
	}

	g_bUserMode = pHeader->LogFileMode & EVENT_TRACE_PRIVATE_LOGGER_MODE;

	wprintf(L"Number of events lost:  %lu\n", pHeader->EventsLost);

	// Use pHeader to access all fields prior to LoggerName.
	// Adjust pHeader based on the pointer size to access
	// all fields after LogFileName. This is required only if
	// you are consuming events on an architecture that is 
	// different from architecture used to write the events.

	if (pHeader->PointerSize != sizeof(PVOID))
	{
		pHeader = (PTRACE_LOGFILE_HEADER)((PUCHAR)pHeader +
			2 * (pHeader->PointerSize - sizeof(PVOID)));
	}
	wprintf(L"Number of buffers lost: %lu\n\n", pHeader->BuffersLost);

	status = ProcessTrace(&g_hTrace, 1, 0, 0);
	if (status != ERROR_SUCCESS && status != ERROR_CANCELLED)
	{
		wprintf(L"ProcessTrace failed with %lu\n", status);
		goto cleanup;
	}

cleanup:
	//	wprintf(L"The process is ended with %lu\n", status);
	if (INVALID_PROCESSTRACE_HANDLE != g_hTrace)
	{
		status = CloseTrace(g_hTrace);
	}
	//	getchar();
}

