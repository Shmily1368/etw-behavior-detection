#pragma once

#include <wbemidl.h>
#include <wmistr.h>
#include <Windows.h>
#include <evntrace.h>
#include <tdh.h>

#include "event_identifier.h"
#include "event_parameter.h"
#include "event_record.h"
#include "event_record_callstack.h"
#include "object_pool.h"
#include "publicstruct.h"
#include"powershell_detector/powershellStruct.h"

const int_32 g_nKProviderMappingSize = 19;
const int_32 g_nKOpcodeNum = 256;
const int_32 g_nKProviderModuloNum = 256;

class EventRecordManager
{
	SINGLETON_DEFINITION(EventRecordManager);
	DISABLE_COPY(EventRecordManager);

public:
	EventRecordManager();
	~EventRecordManager();

	int get_parameter_posistion(EventIdentifier&, parameter_index_enum);
	int query_parameter_posistion(EventIdentifier&, parameter_index_enum);
	void SetWIN7EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	void SetWIN7x86EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	void SetWIN10EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	void SetWIN10x86EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata);
	EventRecord* ParseEventRecord(PEVENT_RECORD raw_rec);
	void RecycleEventRecord(EventRecord* rec);

	EventRecord* ParseVisibleWindowStruct(DWORD processid, DWORD threadid, long long handle , long long left, long long top, long long right, long long bottom, DWORD visible, DWORD toolbar); 
	EventRecord* ParseMouseEvent(DWORD processid, long long buttontype);
	EventRecord* ParseKeyboardEvent(DWORD processid, std::wstring value);
	//EventRecord* ParseRemoveableDeviceEvent(std::wstring value);
    EventRecord* ParseRemoveableDeviceEvent(DWORD serialNum, std::wstring rootPath, std::wstring volumeName, std::wstring fileSystem);
	EventRecord* ParseRansomDetectorEvent(DWORD processid, DWORD parentid,const std::wstring& processname, const std::wstring& parentname, const std::wstring& details, GUID guid);
	EventRecord* ParseRansomTerminateEvent(DWORD processid, const std::wstring& processname, bool terminate, bool stopped, GUID guid);
	EventRecord* ParseIpconfigEvent(std::string ip);
	EventRecord* ParseExtraEventRecord(PEVENT_RECORD raw_rec);
	EventRecord* ParseSecurityEventRecord(std::wstring raw_rec, long pid, long tid);
    EventRecord* ParseZoneIdentifierEvent(ULONG64 time_stamp, DWORD processid, DWORD zoneId, wstring referrerUrl, std::wstring hostUrl, std::wstring fileName);
    EventRecord* ParseRuleIdentifierEvent(EventRecord * ev, SRule srule);
    EventRecord* ParseSysmonDriverLoadedEvent(SDriverLoaded sdl);
    EventRecord* ParseSysmonProcessAccessEvent(SProcessAccess spa);
    EventRecord* ParseHashInfoEvent(EventRecord * ev, std::wstring md5, long fileSize);
	EventRecord* ParsePowershellCheckEvent(powershell_Result ret);
    
	std::map<EventIdentifier, std::vector<EventParameter>> m_mapEventStrucp;
	int m_parameterPosition[g_nKProviderMappingSize][g_nKOpcodeNum][KParametesStringListSize];
private:
	void _InitEventStructMap(const String& file_name);
	bool _ConvertSidtoUname(PVOID sid, std::wstring& uname);
private:
	int m_providerModuloMappingHash[g_nKProviderModuloNum];
	ParameterIndex m_baseParameterIndex;
	std::unordered_map<std::wstring, std::wstring> m_umapSid2Uname;
};

