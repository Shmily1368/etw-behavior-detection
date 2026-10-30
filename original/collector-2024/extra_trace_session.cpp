#include "stdafx.h"
#include "extra_trace_session.h"
#include "on_leave_section_callback.h"
#include "event_record.h"
#include "event_record_extra.h"
#include "filter.h"
#include "event_record_manager.h"
#include "tool_functions.h"
#include"setting.h"
#include <strsafe.h>
#include <tdh.h>
#include"powershell_detector/powershell_detector.h"

#pragma comment(lib, "Rpcrt4.lib")

#define EXTRA_LOGGER_SESSION_NAME	L"Magic-Shield-Extra-Session"
#define EXTRA_LOGGER_SESSION_GUID	{ 0x0AC396A6, 0x069C, 0x49C6, { 0xB7, 0x0B, 0x9F, 0x2F, 0x6C, 0xC2, 0x2E, 0xF7 } }

#define ENABLE_DNS_SESSION
#define ENABLE_POWERSHELL_SESSION

const static std::list<GUID> _enable_guid_list =
{
#ifdef ENABLE_DNS_SESSION
	{ 0x1C95126E, 0x7EEA, 0x49A9, { 0xA3, 0xFE, 0xA3, 0x78, 0xB0, 0x3D, 0xDB, 0x4D } },	//dns;
#endif
#ifdef ENABLE_POWERSHELL_SESSION
	{ 0xA0C1853B, 0x5C40, 0x4B15, { 0x87, 0x66, 0x3C, 0xF1, 0xC5, 0x8F, 0x98, 0x5A } },	//powershell;
#endif
};

ExtraTraceSession::ExtraTraceSession()
{
	_session_prop = NULL;
	_session_handle = 0;
}

ExtraTraceSession::~ExtraTraceSession()
{

}

void ExtraTraceSession::SetTraceProperties(EVENT_TRACE_PROPERTIES * pSessionProperties, ULONG BufferSize)
{
    ZeroMemory(pSessionProperties, BufferSize);
    pSessionProperties->Wnode.BufferSize = BufferSize;
    pSessionProperties->Wnode.Flags = WNODE_FLAG_TRACED_GUID;
    pSessionProperties->Wnode.ClientContext = 1;
    pSessionProperties->Wnode.Guid = EXTRA_LOGGER_SESSION_GUID;
    pSessionProperties->MaximumFileSize = 1;
    pSessionProperties->MaximumBuffers = 1024;
    pSessionProperties->BufferSize = 512;
    pSessionProperties->LogFileMode = EVENT_TRACE_REAL_TIME_MODE;
    pSessionProperties->LogFileNameOffset = 0;
}

bool ExtraTraceSession::StartTraceExec() 
{
    bool ret = false;
    do {
        ULONG buffer_size = sizeof(EVENT_TRACE_PROPERTIES) + sizeof(EXTRA_LOGGER_SESSION_NAME);
        _session_prop = (PEVENT_TRACE_PROPERTIES)malloc(buffer_size);
        if (NULL == _session_prop) {
            WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::StartSession: malloc error, buffer_size = %d", buffer_size);
            break;
        }

        SetTraceProperties(_session_prop, buffer_size);

        ULONG status = StartTrace((PTRACEHANDLE)&_session_handle, EXTRA_LOGGER_SESSION_NAME, _session_prop);
        if (ERROR_SUCCESS != status) {
            if (status == ERROR_ALREADY_EXISTS) {
                status = ::ControlTrace((TRACEHANDLE)NULL, EXTRA_LOGGER_SESSION_NAME, _session_prop, EVENT_TRACE_CONTROL_STOP);
                if (SUCCEEDED(status)) {
                    SetTraceProperties(_session_prop, buffer_size);
                    status = ::StartTrace((PTRACEHANDLE)&_session_handle, EXTRA_LOGGER_SESSION_NAME, _session_prop);
                    if (ERROR_SUCCESS != status) {
                        WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::StartSession: StartTrace failed, err = %d", status);
                        break;
                    }
                }
                else {
                    WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::StartSession: ControlTrace failed, err = %d", status);
                    break;
                }
            }

        }
        
        for (GUID guid : _enable_guid_list) {
            status = EnableTraceEx2(
                _session_handle,
                (LPCGUID)&guid,
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_VERBOSE,
                0,
                0,
                0,
                NULL
            );
            if (ERROR_SUCCESS != status)	break;
           
        }

        if (ERROR_SUCCESS != status) {
            WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::StartSession: EnableTrace failed, err =  %d", status);
            break;
        }

        ret = true;

    } while (0);

    return ret;
}

bool ExtraTraceSession::StartSession()
{
#ifdef ENABLE_POWERSHELL_SESSION
	_CheckPowerShellConfig();
#endif

	system("logman stop \"Magic-Shield-Extra-Session\" -ets > nul");

    _session_worker = std::thread(std::bind(&ExtraTraceSession::_SessionExec, this));
    _session_worker.detach();
	
    auto _eventmonitor_worker = std::thread(std::bind(&ExtraTraceSession::_EventMonitorExec, this));
    _eventmonitor_worker.detach();
	return true;
}

void ExtraTraceSession::StopSession()
{
    _end_flag = true;

	if (_session_handle != 0)
	{
		for (GUID guid : _enable_guid_list)
		{
			EnableTraceEx2(
				_session_handle,
				(LPCGUID)&guid,
				EVENT_CONTROL_CODE_DISABLE_PROVIDER,
				TRACE_LEVEL_INFORMATION,
				0,
				0,
				0,
				NULL
			);
		}
		
		ControlTrace(_session_handle, EXTRA_LOGGER_SESSION_NAME, _session_prop, EVENT_TRACE_CONTROL_STOP);
	}
	
	if (_session_prop)
	{
		free(_session_prop);
		_session_prop = NULL;
	}
}

void ExtraTraceSession::_SessionExec()
{
    while (!_end_flag) {
        if (StartTraceExec())
        {
            EVENT_TRACE_LOGFILE ev_logfile;
            PTRACE_LOGFILE_HEADER ev_logfile_header = &ev_logfile.LogfileHeader;
            ZeroMemory(&ev_logfile, sizeof(EVENT_TRACE_LOGFILE));
            ev_logfile.EventRecordCallback = (PEVENT_RECORD_CALLBACK)(_ConsumeEvent);
            ev_logfile.ProcessTraceMode = PROCESS_TRACE_MODE_EVENT_RECORD | PROCESS_TRACE_MODE_RAW_TIMESTAMP;
            ev_logfile.LoggerName = (LPWSTR)EXTRA_LOGGER_SESSION_NAME;
            ev_logfile.ProcessTraceMode |= PROCESS_TRACE_MODE_REAL_TIME;

            auto ev_trace_handle = OpenTrace(&ev_logfile);
            if (INVALID_PROCESSTRACE_HANDLE == ev_trace_handle) {
                WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_SessionExec: open trace failed with %lu\n", GetLastError());
            }

            if (ev_logfile_header->PointerSize != sizeof(PVOID)) {
                ev_logfile_header = (PTRACE_LOGFILE_HEADER)((PUCHAR)ev_logfile_header +
                    2 * (ev_logfile_header->PointerSize - sizeof(PVOID)));
            }

            ULONG ret = ProcessTrace(&ev_trace_handle, 1, 0, 0);
            if (ret != ERROR_SUCCESS && ret != ERROR_CANCELLED) {
                WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_SessionExec: process trace failed with %lu\n", ret);
            }
            if (_end_flag) {
                return;
            }
        }
        Sleep(100);

        ControlTrace(_session_handle, EXTRA_LOGGER_SESSION_NAME, _session_prop, EVENT_TRACE_CONTROL_STOP);
        if (_session_prop) {
            free(_session_prop);
            _session_prop = NULL;
        }
    }
}

void ExtraTraceSession::_EventMonitorExec()
{
    while (!_end_flag)
    {
        Sleep(10000);

        if (_session_handle != 0) {
            for (GUID guid : _enable_guid_list) {
                auto status = EnableTraceEx2(
                    _session_handle,
                    (LPCGUID)&guid,
                    EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                    TRACE_LEVEL_VERBOSE,
                    0,
                    0,
                    0,
                    NULL
                );
                if (ERROR_SUCCESS != status)	break;
            }
        }

        Sleep(20000);     
    }
}

VOID WINAPI ExtraTraceSession::_ConsumeEvent(PEVENT_RECORD ev_rec)
{
	if (!Filter::GetInstance().FilterBeforeRecInstance(ev_rec->EventHeader.ProviderId.Data1, ev_rec->EventHeader.EventDescriptor.Id, ev_rec->EventHeader.ProcessId))	return;

	EventRecord* ev = EventRecordManager::GetInstance().ParseExtraEventRecord(ev_rec);
	if (!ev)	return;

	ev->InitParse();
	if (!Filter::GetInstance().FilterAfterRecInstance(ev))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(ev);
		return;
	}

	ev->parse();

	//get process_id to filter
	//mainly filter PID in black list, because fileiofilecreate and fileiocreate is need to match rename event and macro ,we do not filter it here
	if (!Filter::FilterAfterParseRecord(ev))
	{
		EventRecordManager::GetInstance().RecycleEventRecord(ev);
		return;
	}

	ev->SetProcessTcpPreEventRecord(ev);
	//
	if (ev_rec->EventHeader.ProviderId.Data1 == ETWPowerShell&& Setting::GetInstance().enable_powershell_detector()) {
		powershell_detector::GetInstance().AddScript(ToolFunctions::WStringToString(ev->m_vctParameterList[0].s), ev_rec->EventHeader.ProcessId, ev_rec->EventHeader.ThreadId);;	
	}
	
	if (!ev->Output())
	{
		EventRecordManager::GetInstance().RecycleEventRecord(ev);
	}
}

void ExtraTraceSession::_CheckPowerShellConfig()
{
	LSTATUS ret;

	std::wstring powershell_key_root = L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell";
	HKEY hkey_pws_root;
	ret = ToolFunctions::RegOpenKeyForce(HKEY_LOCAL_MACHINE, powershell_key_root, hkey_pws_root);
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: open key failed, path = %s , ret = %lu", powershell_key_root.c_str(), ret);
		return;
	}
	DECLARE_LEAVE_SECTION_CALLBACK([hkey_pws_root]() { RegCloseKey(hkey_pws_root); });

	HKEY hkey_pws_module_logging;
	ret = ToolFunctions::RegOpenKeyForce(hkey_pws_root, L"ModuleLogging", hkey_pws_module_logging);
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: open key failed, path = ModuleLogging, ret = %lu", ret);
		return;
	}
	DECLARE_LEAVE_SECTION_CALLBACK([hkey_pws_module_logging]() { RegCloseKey(hkey_pws_module_logging); });

	DWORD value_dw = 1;
	ret = ToolFunctions::RegQuerySetValue(hkey_pws_module_logging, L"EnableModuleLogging", REG_DWORD, (LPBYTE)(&value_dw), sizeof(value_dw));
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: query set value failed, name = EnableModuleLogging, ret = %lu", ret);
		return;
	}

	HKEY hkey_pws_module_names;
	ret = ToolFunctions::RegOpenKeyForce(hkey_pws_module_logging, L"ModuleNames", hkey_pws_module_names);
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: open key failed, path = ModuleLogging, ret = %lu", ret);
		return;
	}
	DECLARE_LEAVE_SECTION_CALLBACK([hkey_pws_module_names]() { RegCloseKey(hkey_pws_module_names); });

	TCHAR value_str[128] = L"Microsoft.PowerShell.*";
	ret = ToolFunctions::RegQuerySetValue(hkey_pws_module_names, L"Microsoft.PowerShell.*", REG_SZ, (LPBYTE)value_str, (DWORD)((wcslen(value_str) + 1) * 2));
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: query set value failed, path = Microsoft.PowerShell.*, ret = %lu", ret);
		return;
	}

	HKEY hkey_script_block_logging;
	ret = ToolFunctions::RegOpenKeyForce(hkey_pws_root, L"ScriptBlockLogging", hkey_script_block_logging);
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: open key failed, path = ScriptBlockLogging, ret = %lu", ret);
		return;
	}
	DECLARE_LEAVE_SECTION_CALLBACK([hkey_script_block_logging]() { RegCloseKey(hkey_script_block_logging); });

	value_dw = 1;
	ret = ToolFunctions::RegQuerySetValue(hkey_script_block_logging, L"EnableScriptBlockLogging", REG_DWORD, (LPBYTE)(&value_dw), sizeof(value_dw));
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: query set value failed, name = EnableScriptBlockLogging, ret = %lu", ret);
		return;
	}

	HKEY hkey_transcription;
	ret = ToolFunctions::RegOpenKeyForce(hkey_pws_root, L"Transcription", hkey_transcription);
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: open key failed, path = Transcription, ret = %lu", ret);
		return;
	}
	DECLARE_LEAVE_SECTION_CALLBACK([hkey_transcription]() { RegCloseKey(hkey_transcription); });

	value_dw = 1;
	ret = ToolFunctions::RegQuerySetValue(hkey_transcription, L"EnableTranscripting", REG_DWORD, (LPBYTE)(&value_dw), sizeof(value_dw));
	if (ret != ERROR_SUCCESS)
	{
		WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: query set value failed, name = EnableTranscripting, ret = %lu", ret);
		return;
	}
    // add by zxw on 20200819 set powershell dir
    TCHAR dir_str[MAX_PATH] = { 0 };
    GetCurrentDirectory(MAX_PATH, dir_str);
    std::wstring str_value = dir_str + std::wstring(L"\\powershelloutput");
    ret = ToolFunctions::RegQuerySetValue(hkey_transcription, L"OutputDirectory", REG_SZ, (LPBYTE)str_value.c_str(), (DWORD)((wcslen(str_value.c_str()) + 1) * 2));
    if (ret != ERROR_SUCCESS) {
        WriteLog4cPlus(ERROR_LEVEL, L"ExtraTraceSession::_CheckPowerShellConfig: query set value failed, name = OutputDirectory, ret = %lu", ret);
        return;
    }
}
