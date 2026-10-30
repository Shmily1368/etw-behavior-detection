#include "stdafx.h"
#include "event_record_manager.h"
#include "parameter_index.h"
#include "event_parameter.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "filter.h"
#include "tool_functions.h"
#include "setting.h"
#include "event_record.h"
#include "event_record_extra.h"
#include "public_json_interface.h"
//#include <tdh.h> 

#include <Windows.h>
#include "process_event_info.h"
#include <fstream>
#include <atlconv.h>
#include <Sddl.h>

//Mapping (providerid mode 256) to hash value
//providerid mode 256 is unique
EventRecordManager::EventRecordManager()
{
	m_providerModuloMappingHash[0xcd] = 0;//ALPC
	m_providerModuloMappingHash[0xd1] = 1;//Thread
	m_providerModuloMappingHash[0x39] = 2;//FileIO
	m_providerModuloMappingHash[0xd4] = 3;//DiskIO
	m_providerModuloMappingHash[0xb4] = 4;//PerfInfo
	m_providerModuloMappingHash[0xd3] = 5;//PageFault
	m_providerModuloMappingHash[0xc0] = 6;//Tcp
	m_providerModuloMappingHash[0xc5] = 7;//Udp
	m_providerModuloMappingHash[0xd0] = 8;//Process
	m_providerModuloMappingHash[0x2e] = 9;//Registry
	m_providerModuloMappingHash[0x92] = 10;//Splitlo
	m_providerModuloMappingHash[0x1d] = 11;//Image
	m_providerModuloMappingHash[0xde] = 12;//Stackwalk
	m_providerModuloMappingHash[0x00] = 13;//VisibleWindow
	m_providerModuloMappingHash[0x01] = 14;//Mouse 
	m_providerModuloMappingHash[0x02] = 15;//Keyboard
	m_providerModuloMappingHash[0x03] = 16;//AdditionData
	m_providerModuloMappingHash[0x6e] = 17;//dns
	m_providerModuloMappingHash[0x59] = 18;//powershell
	for (int i = 0; i != g_nKProviderMappingSize; i++)
	{
		for (int j = 0; j != g_nKOpcodeNum; j++)
		{
			for (int k = 0; k != KParametesStringListSize; k++)
			{
				m_parameterPosition[i][j][k] = -1;
			}
		}
	}

	_InitEventStructMap(Setting::GetInstance().format_file());
}

EventRecordManager::~EventRecordManager()
{

}

int EventRecordManager::get_parameter_posistion(EventIdentifier& event_identifier, parameter_index_enum name)
{
	int ix = m_parameterPosition[m_providerModuloMappingHash[event_identifier.provider_id() & 0xff]][event_identifier.opcode()% g_nKOpcodeNum][name];
	if (ix == -1)
	{
		EventParameter parameter;
		parameter.name = name;
		parameter.offset = -1;
		parameter.length = -1;
		ix = (int)m_mapEventStrucp[event_identifier].size();
		m_mapEventStrucp[event_identifier].push_back(parameter);
		m_parameterPosition[m_providerModuloMappingHash[event_identifier.provider_id() & 0xff]][event_identifier.opcode()% g_nKOpcodeNum][name] = ix;
	}
	return ix;
}

int EventRecordManager::query_parameter_posistion(EventIdentifier& event_identifier, parameter_index_enum name)
{
	return m_parameterPosition[m_providerModuloMappingHash[event_identifier.provider_id() & 0xff]][event_identifier.opcode()% g_nKOpcodeNum][name];
}

EventRecord* EventRecordManager::ParseEventRecord(PEVENT_RECORD raw_rec)
{
	EventRecord* output = nullptr;
	switch (raw_rec->EventHeader.ProviderId.Data1)
	{
	case ETWFileIo:
		output = new EventRecordFileio(raw_rec);
		break;
	case ETWThread:
		output = new EventRecordThread(raw_rec);
		break;
	case ETWProcess:
		output = new EventRecordProcess(raw_rec);
		break;
	case ETWImage:
		output = new EventRecordImage(raw_rec);
		break;
	case ETWRegistry:
		output = new EventRecordRegistry(raw_rec);
		break;
	case ETWALPC:
		output = new EventRecordAlpc(raw_rec);
		break;
	case ETWDiskIo:
		output = new EventRecordDiskio(raw_rec);
		break;
	case ETWPerfInfo:
		//output = new EventRecordPerfInfo(raw_rec);
		return output;
		break;
	case ETWTcpIp:
		output = new EventRecordTcpip(raw_rec);
		break;
	case ETWUdpIp:
		output = new EventRecordUdpip(raw_rec);
		break;
	case ETWStackWalk:
		output = new EventRecordCallstack(raw_rec);
		return output;
	default:
		output = new EventRecordUnknown();
		return output;
	};

	//hard code to parse event_record data
	ULONG64 pUserData = (ULONG64)raw_rec->UserData;

	if (ToolFunctions::GetIsWowOS64Bit())
	{
		if (ToolFunctions::GetOsVersion() == EM_OsVersion::WIN7)
		{
			//optimize,fix chips，未来放入event_record中作为event_record的成员函数
			SetWIN7EventInfo(output, raw_rec->EventHeader.EventDescriptor.Opcode, raw_rec->EventHeader.ProviderId.Data1, pUserData);
		}
		else
		{
			//fix chips,need test
			SetWIN10EventInfo(output, raw_rec->EventHeader.EventDescriptor.Opcode, raw_rec->EventHeader.ProviderId.Data1, pUserData);
		}
	}
	else
	{
		if (ToolFunctions::GetOsVersion() == EM_OsVersion::WIN7)
		{
			SetWIN7x86EventInfo(output, raw_rec->EventHeader.EventDescriptor.Opcode, raw_rec->EventHeader.ProviderId.Data1, pUserData);
		}
		else
		{
			SetWIN10x86EventInfo(output, raw_rec->EventHeader.EventDescriptor.Opcode, raw_rec->EventHeader.ProviderId.Data1, pUserData);
		}
	}
	

	//no hard code
	//ix = event_strucp_map.find(output->event_identifier_);
	//if (ix != event_strucp_map.end())
	//{
	//	ParameterValue parameter_value;
	//	pUserData = (ULONG64)pEvent->UserData;
	//	output->thread_id_ = pEvent->EventHeader.ThreadId;
	//	output->process_id_ = pEvent->EventHeader.ProcessId;
	//	output->processor_id_ = pEvent->BufferContext.ProcessorNumber;
	//	for (int i = 0; i != ix->second.size(); i++){
	//		if (ix->second[i].length == 2){
	//			parameter_value.d = *(short*)(pUserData + ix->second[i].offset);
	//			output->parameter_list_.push_back(parameter_value);
	//		}
	//		else
	//			if (ix->second[i].length == 8){
	//				parameter_value.d = *(long long*)(pUserData + ix->second[i].offset);
	//				output->parameter_list_.push_back(parameter_value);
	//			}
	//			else
	//				if (ix->second[i].length == 4){
	//					parameter_value.d = *(DWORD*)(pUserData + ix->second[i].offset);
	//					output->parameter_list_.push_back(parameter_value);
	//				}
	//				else
	//					if (ix->second[i].length == 1){
	//						parameter_value.d = *(char*)(pUserData + ix->second[i].offset);
	//						output->parameter_list_.push_back(parameter_value);
	//					}
	//					else {
	//						if (temp_EventIdentifier.provider_id == ETWProcess && (ix->second.size() == 11) && (i == 8)) {//0 is SID
	//							USES_CONVERSION;
	//							LPWSTR* chSID = new LPWSTR;
	//							wchar_t* temp_wchar_t;
	//							int ret = ConvertSidToStringSid((PVOID)(pUserData + ix->second[i].offset), chSID);
	//							temp_wchar_t = (wchar_t*)*chSID;
	//							parameter_value.s = temp_wchar_t;
	//							output->parameter_list_.push_back(parameter_value);
	//							pUserData += GetLengthSid((PVOID)(pUserData + ix->second[i].offset));
	//							i++;
	//							int len = strlen((char *)(pUserData + ix->second[i].offset)) + 1;
	//							temp_wchar_t = new wchar_t[len+1];
	//							MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + ix->second[i].offset), len, temp_wchar_t, len);
	//							parameter_value.s = temp_wchar_t;
	//							output->parameter_list_.push_back(parameter_value);
	//							pUserData += len;
	//							delete chSID;
	//							delete temp_wchar_t;
	//						}
	//						else
	//							if (ix->second[i].length == 0) {
	//								parameter_value.s = (wchar_t*)(pUserData + ix->second[i].offset);
	//								output->parameter_list_.push_back(parameter_value);
	//								pUserData += (wcslen((wchar_t*)(pUserData + ix->second[i].offset)) + 1);
	//							};
	//					}
	//	}
	//}
	//else
	//{
	//	output->useless = true;
	//	output->event_identifier_.opcode = -1;
	//		
	//}
 	return output;
}

void EventRecordManager::RecycleEventRecord(EventRecord* rec)
{
	SAFE_DELETE(rec);
}

void EventRecordManager::SetWIN7EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata)
{
	ULONG64 pUserData = pdata;
	ParameterValue parameter_value;
	switch (provider_id)
	{
	case 1030727889:
	{
		if (EM_ThreadEventOPC::ThreadContextSwitch == opcode)
		{
			//NewThreadId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_ThreadEventOPC::ThreadStart == opcode || EM_ThreadEventOPC::ThreadDCStart == opcode || EM_ThreadEventOPC::ThreadEnd == opcode)
		{
			//ProcessId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TThreadId 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 1030727888:
	{
		if (EM_ProcessEventOPC::ProcessStart == opcode || EM_ProcessEventOPC::ProcessDCStart == opcode)
		{
			//ProcessID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ParentID 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//UserSID  48 0
			USES_CONVERSION;
			wchar_t* temp_wchar_t;
			// mod by zxw on 20191204
			std::wstring uname;
			_ConvertSidtoUname((PVOID)(pUserData + 48), uname);
			parameter_value.s = uname;
			inRecord->m_vctParameterList.push_back(parameter_value);
			//
// 			LPWSTR* chSID = new LPWSTR;
// 			int ret = ConvertSidToStringSid((PVOID)(pUserData + 48), chSID);
// 			temp_wchar_t = (wchar_t*)*chSID;
// 			parameter_value.s = temp_wchar_t;
// 			inRecord->parameter_list_.push_back(parameter_value);

 			pUserData += GetLengthSid((PVOID)(pUserData + 48));

			//ImageFileName 48 0
			int len = (int)strlen((char *)(pUserData + 48)) + 1;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 48), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			//delete chSID;
			delete[] temp_wchar_t;

			//CommandLine 48 0;be used to data analyze, to fix chips;
			parameter_value.s = (wchar_t*)(pUserData + 48);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 48)) + 1);
		}
		else if (EM_ProcessEventOPC::ProcessEnd == opcode)
		{
			//ProcessID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//略过UserSID  48 0,读取imagefilename;
			USES_CONVERSION;
			pUserData += GetLengthSid((PVOID)(pUserData + 48));

			//ImageFileName 48 0
			int len = (int)strlen((char *)(pUserData + 48)) + 1;
			wchar_t* temp_wchar_t;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 48), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			delete[] temp_wchar_t;
		}
		break;
	}

	case 2429279289:
	{
		if (EM_FileioEventOPC::FileIoRead == opcode || EM_FileioEventOPC::FileIoWirte == opcode)
		{
			// add by zxw on 20191108 add ransom
			//Offset 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IrpPtr 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoSize 40 4
			parameter_value.d = *(DWORD*)(pUserData + 40);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoFlags 44 4
			parameter_value.d = *(DWORD*)(pUserData + 44);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//

			//TTID 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 24 8
			parameter_value.d = *(long long*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 32 8
			parameter_value.d = *(long long*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioFileCreateEvent == opcode || EM_FileioEventOPC::FileioNameEvent == opcode)
		{
			//FileObject 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 8 0
			parameter_value.s = (wchar_t*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 8)) + 1);

		}
		else if (EM_FileioEventOPC::FileioCreateEvent == opcode)
		{
			// mod by zxw on 20191113 add IrpPtr、CreateOptions、FileAttributes、ShareAccess
			//IrpPtr 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//TTID 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileObject 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//CreateOptions 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileAttributes 28 4
			parameter_value.d = *(DWORD*)(pUserData + 28);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//ShareAccess 32 4
			parameter_value.d = *(DWORD*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//OpenPath 36 0
			parameter_value.s = (wchar_t*)(pUserData + 36);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 36)) + 1);
			/*
			//TTID 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->parameter_list_.push_back(parameter_value);

			//FileObject 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->parameter_list_.push_back(parameter_value);

			//OpenPath 36 0
			parameter_value.s = (wchar_t*)(pUserData + 36);
			inRecord->parameter_list_.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 36)) + 1);
			*/
		}
		else if (EM_FileioEventOPC::FileioRenameEvent == opcode || EM_FileioEventOPC::FileioClose == opcode || EM_FileioEventOPC::FileIoDelete == opcode)
		{
			//TTID 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 24 8
			parameter_value.d = *(long long*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);

		}
		// add by zxw on 20191111
		else if (EM_FileioEventOPC::FileioDirEnumerationEvent == opcode || EM_FileioEventOPC::FileIoCleanup == opcode)
		{
			//IrpPtr 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TTID 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 749821213:
	{
		if (EM_ImageEventOPC::ImageDCStart == opcode || EM_ImageEventOPC::ImageLoad == opcode || EM_ImageEventOPC::ImageUnload == opcode)
		{
			//ImageBase 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ImageSize 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ProcessId 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 56 0
			parameter_value.s = (wchar_t*)(pUserData + 56);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 56)) + 1);
		}
		break;
	}
	case 2586315456://TCP
	case 3208270021://UDP
	{
		//tcp/ip  udp 的都只要一个pid  PID 0 4
		parameter_value.d = *(DWORD*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//size 4 4
		parameter_value.d = *(DWORD*)(pUserData + 4);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//daddr 8 4;
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//saddr 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//dport 16 2
		parameter_value.d = *(USHORT*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//sport 18 2
		parameter_value.d = *(USHORT*)(pUserData + 18);
		inRecord->m_vctParameterList.push_back(parameter_value);

		////seqnum 20 4
		//parameter_value.d = *(DWORD*)(pUserData + 20);
		//inRecord->parameter_list_.push_back(parameter_value);

		////connid 24 8
		//parameter_value.d = *(long long*)(pUserData + 24);
		//inRecord->parameter_list_.push_back(parameter_value);
		break;
	}
	case 3458056116:
	{
		parameter_value.d = *(long long*)pUserData;
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
    case 2924704302:    //Registry
    {
        //InitialTime 0 8
        parameter_value.d = *(long long*)(pUserData + 0);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //Status 8 4
        parameter_value.d = *(DWORD*)(pUserData + 8);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //Index 12 4
        parameter_value.d = *(DWORD*)(pUserData + 12);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //KeyHandle 16 8
        parameter_value.d = *(long long*)(pUserData + 16);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //KeyName 24 0
        parameter_value.s = (wchar_t*)(pUserData + 24);
        inRecord->m_vctParameterList.push_back(parameter_value);
        pUserData += (wcslen((wchar_t*)(pUserData + 24)) + 1);

        break;
    }
	default:
	{
		inRecord->m_bUseless = true;
		inRecord->m_eventIdentifier.opcode(-1);
		break;
	}
	}
	return;
}

void EventRecordManager::SetWIN7x86EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata)
{
	ULONG64 pUserData = pdata;
	ParameterValue parameter_value;
	switch (provider_id)
	{
	case 1030727889:
	{
		if (EM_ThreadEventOPC::ThreadContextSwitch == opcode)
		{
			//NewThreadId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_ThreadEventOPC::ThreadStart == opcode || EM_ThreadEventOPC::ThreadDCStart == opcode || EM_ThreadEventOPC::ThreadEnd == opcode)
		{
			//ProcessId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TThreadId 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 1030727888:
	{
		if (EM_ProcessEventOPC::ProcessStart == opcode || EM_ProcessEventOPC::ProcessDCStart == opcode)
		{
			//ProcessID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ParentID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//UserSID  32 0
			USES_CONVERSION;
			wchar_t* temp_wchar_t;
			std::wstring uname;
			_ConvertSidtoUname((PVOID)(pUserData + 32), uname);
			parameter_value.s = uname;
			inRecord->m_vctParameterList.push_back(parameter_value);

			pUserData += GetLengthSid((PVOID)(pUserData + 32));

			//ImageFileName 32 0
			int len = (int)strlen((char *)(pUserData + 32)) + 1;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 32), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			//delete chSID;
			delete[] temp_wchar_t;

			//CommandLine 32 0;be used to data analyze, to fix chips;
			parameter_value.s = (wchar_t*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 32)) + 1);
		}
		else if (EM_ProcessEventOPC::ProcessEnd == opcode)
		{
			//ProcessID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//略过UserSID  32 0,读取imagefilename;
			USES_CONVERSION;
			pUserData += GetLengthSid((PVOID)(pUserData + 32));

			//ImageFileName 32 0
			int len = (int)strlen((char *)(pUserData + 32)) + 1;
			wchar_t* temp_wchar_t;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 32), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			delete[] temp_wchar_t;
		}
		break;
	}

	case 2429279289:
	{
		if (EM_FileioEventOPC::FileIoRead == opcode || EM_FileioEventOPC::FileIoWirte == opcode)
		{
			// add by zxw on 20191108 add ransom
			//Offset 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IrpPtr 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoSize 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoFlags 28 4
			parameter_value.d = *(DWORD*)(pUserData + 28);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TTID 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 20 4
			parameter_value.d = *(DWORD*)(pUserData + 20);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioFileCreateEvent == opcode || EM_FileioEventOPC::FileioNameEvent == opcode)
		{
			//FileObject 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 4 0
			parameter_value.s = (wchar_t*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 4)) + 1);

		}
		else if (EM_FileioEventOPC::FileioCreateEvent == opcode)
		{
			// mod by zxw on 20191113 add IrpPtr、CreateOptions、FileAttributes、ShareAccess
			//IrpPtr 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//TTID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileObject 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//CreateOptions 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileAttributes 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//ShareAccess 20 4
			parameter_value.d = *(DWORD*)(pUserData + 20);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//OpenPath 24 0
			parameter_value.s = (wchar_t*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 24)) + 1);
		}
		else if (EM_FileioEventOPC::FileioRenameEvent == opcode || EM_FileioEventOPC::FileioClose == opcode || EM_FileioEventOPC::FileIoDelete == opcode)
		{
			//TTID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

		}
		// add by zxw on 20191111
		else if (EM_FileioEventOPC::FileioDirEnumerationEvent == opcode || EM_FileioEventOPC::FileIoCleanup == opcode)
		{
			//IrpPtr 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TTID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 749821213:
	{
		if (EM_ImageEventOPC::ImageDCStart == opcode || EM_ImageEventOPC::ImageLoad == opcode || EM_ImageEventOPC::ImageUnload == opcode)
		{
			//ImageBase 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ImageSize 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ProcessId 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 44 0
			parameter_value.s = (wchar_t*)(pUserData + 44);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 44)) + 1);
		}
		break;
	}
	case 2586315456://TCP
	case 3208270021://UDP
	{
		//tcp/ip  udp 的都只要一个pid  PID 0 4
		parameter_value.d = *(DWORD*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//size 4 4
		parameter_value.d = *(DWORD*)(pUserData + 4);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//daddr 8 4;
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//saddr 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//dport 16 2
		parameter_value.d = *(USHORT*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//sport 18 2
		parameter_value.d = *(USHORT*)(pUserData + 18);
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
	case 3458056116:
	{
		parameter_value.d = *(DWORD*)pUserData;
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
	case 2924704302:    //Registry
	{
		//InitialTime 0 8
		parameter_value.d = *(long long*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//Status 8 4
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//Index 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//KeyHandle 16 4
		parameter_value.d = *(DWORD*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//KeyName 20 0
		parameter_value.s = (wchar_t*)(pUserData + 20);
		inRecord->m_vctParameterList.push_back(parameter_value);
		pUserData += (wcslen((wchar_t*)(pUserData + 20)) + 1);

		break;
	}
	default:
	{
		inRecord->m_bUseless = true;
		inRecord->m_eventIdentifier.opcode(-1);
		break;
	}
	}
	return;
}

void EventRecordManager::SetWIN10EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata)
{
	ULONG64 pUserData = pdata;
	ParameterValue parameter_value;
	switch (provider_id)
	{
	case 1030727889:
	{
		if (EM_ThreadEventOPC::ThreadContextSwitch == opcode)
		{
			//NewThreadId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_ThreadEventOPC::ThreadStart == opcode || EM_ThreadEventOPC::ThreadDCStart == opcode || EM_ThreadEventOPC::ThreadEnd == opcode)
		{
			//ProcessId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TThreadId 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 1030727888:
	{
		if (EM_ProcessEventOPC::ProcessStart == opcode || EM_ProcessEventOPC::ProcessDCStart == opcode)
		{
			//ProcessID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ParentID 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//UserSID  52 0
			USES_CONVERSION;
			wchar_t* temp_wchar_t;
			/*
			LPWSTR* chSID = new LPWSTR;
			int ret = ConvertSidToStringSid((PVOID)(pUserData + 52), chSID);
			temp_wchar_t = (wchar_t*)*chSID;			
			parameter_value.s = temp_wchar_t;
			inRecord->parameter_list_.push_back(parameter_value);
			*/
			// mod by zxw on 20191204
			std::wstring uname;
			_ConvertSidtoUname((PVOID)(pUserData + 52), uname);
			parameter_value.s = uname;
			inRecord->m_vctParameterList.push_back(parameter_value);
			//

			pUserData += GetLengthSid((PVOID)(pUserData + 52));
			//ImageFileName 52 0
			int len = (int)strlen((char *)(pUserData + 52)) + 1;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 52), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			//delete chSID;
			delete[] temp_wchar_t;

			//CommandLine 52 0
			parameter_value.s = (wchar_t*)(pUserData + 52);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 52)) + 1);
		}
		else if (EM_ProcessEventOPC::ProcessEnd == opcode)
		{
			//ProcessID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//略过UserSID 52 0,读取imagefilename;
			USES_CONVERSION;
			pUserData += GetLengthSid((PVOID)(pUserData + 52));

			//ImageFileName 52 0
			int len = (int)strlen((char *)(pUserData + 52)) + 1;
			wchar_t* temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 52), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			delete[] temp_wchar_t;
		}
		break;
	}

	case 2429279289:
	{
		if (EM_FileioEventOPC::FileIoRead == opcode || EM_FileioEventOPC::FileIoWirte == opcode)
		{
			// add by zxw on 20191108 add ransom
			//Offset 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IrpPtr 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoSize 36 4
			parameter_value.d = *(DWORD*)(pUserData + 36);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoFlags 40 4
			parameter_value.d = *(DWORD*)(pUserData + 40);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//

			//TTID 32 4
			parameter_value.d = *(DWORD*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 24 8
			parameter_value.d = *(long long*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileIoRenamePath == opcode)
		{
			//TTID 32 4
			parameter_value.d = *(DWORD*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioFileCreateEvent == opcode || EM_FileioEventOPC::FileioNameEvent == opcode)
		{
			//FileObject 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 8 0
			parameter_value.s = (wchar_t*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 8)) + 1);
		}
		else if (EM_FileioEventOPC::FileioCreateEvent == opcode)
		{
			// mod by zxw on 20191113 add IrpPtr、CreateOptions、FileAttributes、ShareAccess
			//IrpPtr 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//TTID 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//CreateOptions 20 4
			parameter_value.d = *(DWORD*)(pUserData + 20);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileAttributes 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//ShareAccess 28 4
			parameter_value.d = *(DWORD*)(pUserData + 28);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//OpenPath 32 0
			parameter_value.s = (wchar_t*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 32)) + 1);
			/*
			//TTID 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->parameter_list_.push_back(parameter_value);

			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->parameter_list_.push_back(parameter_value);

			//OpenPath 32 0
			parameter_value.s = (wchar_t*)(pUserData + 32);
			inRecord->parameter_list_.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 32)) + 1);
			*/
		}
		else if (EM_FileioEventOPC::FileioRenameEvent == opcode || EM_FileioEventOPC::FileIoDelete == opcode)
		{
			//TTID 32 4
			parameter_value.d = *(DWORD*)(pUserData + 32);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioClose == opcode)
		{
			//TTID 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 16 8
			parameter_value.d = *(long long*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		// add by zxw on 20191111
		else if (EM_FileioEventOPC::FileioDirEnumerationEvent == opcode || EM_FileioEventOPC::FileIoCleanup == opcode)
		{
			//IrpPtr 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
		
			//TTID 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		
		break;
	}
	case 749821213:
	{
		if (EM_ImageEventOPC::ImageDCStart == opcode || EM_ImageEventOPC::ImageLoad == opcode || EM_ImageEventOPC::ImageUnload == opcode)
		{
			//ImageBase 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ImageSize 8 8
			parameter_value.d = *(long long*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ProcessId 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 56 0
			parameter_value.s = (wchar_t*)(pUserData + 56);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 56)) + 1);
		}
		break;
	}
	case 2586315456:
	case 3208270021:
	{
		//tcp/ip  udp 的都只要一个pid  PID 0 4
		parameter_value.d = *(DWORD*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

        //size 4 4
        parameter_value.d = *(DWORD*)(pUserData + 4);
        inRecord->m_vctParameterList.push_back(parameter_value);

		//daddr 8 4
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//saddr 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//dport 16 2
		parameter_value.d = *(USHORT*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//sport 18 2
		parameter_value.d = *(USHORT*)(pUserData + 18);
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
	case 3458056116:
	{
		parameter_value.d = *(long long*)pUserData;
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
    case 2924704302:    //Registry
    { 
        //InitialTime 0 8
        parameter_value.d = *(long long*)(pUserData + 0);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //Status 8 4
        parameter_value.d = *(DWORD*)(pUserData + 8);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //Index 12 4
        parameter_value.d = *(DWORD*)(pUserData + 12);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //KeyHandle 16 8
        parameter_value.d = *(long long*)(pUserData + 16);
        inRecord->m_vctParameterList.push_back(parameter_value);

        //KeyName 24 0
        parameter_value.s = (wchar_t*)(pUserData + 24);
        inRecord->m_vctParameterList.push_back(parameter_value);
        pUserData += (wcslen((wchar_t*)(pUserData + 24)) + 1);

        break;
    }
	default:
	{
		inRecord->m_bUseless = true;
		inRecord->m_eventIdentifier.opcode(-1);
		break;
	}
	}
	return;
}

void EventRecordManager::SetWIN10x86EventInfo(EventRecord* inRecord, int opcode, int provider_id, ULONG64 pdata)
{
	ULONG64 pUserData = pdata;
	ParameterValue parameter_value;
	switch (provider_id)
	{
	case 1030727889:
	{
		if (EM_ThreadEventOPC::ThreadContextSwitch == opcode)
		{
			//NewThreadId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_ThreadEventOPC::ThreadStart == opcode || EM_ThreadEventOPC::ThreadDCStart == opcode || EM_ThreadEventOPC::ThreadEnd == opcode)
		{
			//ProcessId 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TThreadId 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		break;
	}
	case 1030727888:
	{
		if (EM_ProcessEventOPC::ProcessStart == opcode || EM_ProcessEventOPC::ProcessDCStart == opcode)
		{
			//ProcessID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ParentID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//UserSID  36 0
			USES_CONVERSION;
			wchar_t* temp_wchar_t;

			std::wstring uname;
			_ConvertSidtoUname((PVOID)(pUserData + 36), uname);
			parameter_value.s = uname;
			inRecord->m_vctParameterList.push_back(parameter_value);
			//

			pUserData += GetLengthSid((PVOID)(pUserData + 36));
			//ImageFileName 36 0
			int len = (int)strlen((char *)(pUserData + 36)) + 1;
			temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 36), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			//delete chSID;
			delete[] temp_wchar_t;

			//CommandLine 36 0
			parameter_value.s = (wchar_t*)(pUserData + 36);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 36)) + 1);
		}
		else if (EM_ProcessEventOPC::ProcessEnd == opcode)
		{
			//ProcessID 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			USES_CONVERSION;
			pUserData += GetLengthSid((PVOID)(pUserData + 36));

			//ImageFileName 36 0
			int len = (int)strlen((char *)(pUserData + 36)) + 1;
			wchar_t* temp_wchar_t = new wchar_t[len + 1];
			MultiByteToWideChar(CP_ACP, 0, (char *)(pUserData + 36), len, temp_wchar_t, len);
			parameter_value.s = temp_wchar_t;
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += len;
			delete[] temp_wchar_t;
		}
		break;
	}

	case 2429279289:
	{
		if (EM_FileioEventOPC::FileIoRead == opcode || EM_FileioEventOPC::FileIoWirte == opcode)
		{
			// add by zxw on 20191108 add ransom
			//Offset 0 8
			parameter_value.d = *(long long*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IrpPtr 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoSize 24 4
			parameter_value.d = *(DWORD*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//IoFlags 28 4
			parameter_value.d = *(DWORD*)(pUserData + 28);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TTID 20 4
			parameter_value.d = *(DWORD*)(pUserData + 20);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileIoRenamePath == opcode)
		{
			//TTID 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioFileCreateEvent == opcode || EM_FileioEventOPC::FileioNameEvent == opcode)
		{
			//FileObject 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 4 0
			parameter_value.s = (wchar_t*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 4)) + 1);
		}
		else if (EM_FileioEventOPC::FileioCreateEvent == opcode)
		{
			// mod by zxw on 20191113 add IrpPtr、CreateOptions、FileAttributes、ShareAccess
			//IrpPtr 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//TTID 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileObject 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//CreateOptions 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//FileAttributes 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//ShareAccess 20 4
			parameter_value.d = *(DWORD*)(pUserData + 20);
			inRecord->m_vctParameterList.push_back(parameter_value);
			//OpenPath 24 0
			parameter_value.s = (wchar_t*)(pUserData + 24);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 24)) + 1);
		}
		else if (EM_FileioEventOPC::FileioRenameEvent == opcode || EM_FileioEventOPC::FileIoDelete == opcode)
		{
			//TTID 16 4
			parameter_value.d = *(DWORD*)(pUserData + 16);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		else if (EM_FileioEventOPC::FileioClose == opcode)
		{
			//TTID 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileKey 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}
		// add by zxw on 20191111
		else if (EM_FileioEventOPC::FileioDirEnumerationEvent == opcode || EM_FileioEventOPC::FileIoCleanup == opcode)
		{
			//IrpPtr 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//TTID 12 4
			parameter_value.d = *(DWORD*)(pUserData + 12);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileObject 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);
		}

		break;
	}
	case 749821213:
	{
		if (EM_ImageEventOPC::ImageDCStart == opcode || EM_ImageEventOPC::ImageLoad == opcode || EM_ImageEventOPC::ImageUnload == opcode)
		{
			//ImageBase 0 4
			parameter_value.d = *(DWORD*)(pUserData + 0);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ImageSize 4 4
			parameter_value.d = *(DWORD*)(pUserData + 4);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//ProcessId 8 4
			parameter_value.d = *(DWORD*)(pUserData + 8);
			inRecord->m_vctParameterList.push_back(parameter_value);

			//FileName 44 0
			parameter_value.s = (wchar_t*)(pUserData + 44);
			inRecord->m_vctParameterList.push_back(parameter_value);
			pUserData += (wcslen((wchar_t*)(pUserData + 44)) + 1);
		}
		break;
	}
	case 2586315456:
	case 3208270021:
	{
		//tcp/ip  udp 的都只要一个pid  PID 0 4
		parameter_value.d = *(DWORD*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//size 4 4
		parameter_value.d = *(DWORD*)(pUserData + 4);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//daddr 8 4
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//saddr 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//dport 16 2
		parameter_value.d = *(USHORT*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//sport 18 2
		parameter_value.d = *(USHORT*)(pUserData + 18);
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
	case 3458056116:
	{
		parameter_value.d = *(DWORD*)pUserData;
		inRecord->m_vctParameterList.push_back(parameter_value);
		break;
	}
	case 2924704302:    //Registry
	{
		//InitialTime 0 8
		parameter_value.d = *(long long*)(pUserData + 0);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//Status 8 4
		parameter_value.d = *(DWORD*)(pUserData + 8);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//Index 12 4
		parameter_value.d = *(DWORD*)(pUserData + 12);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//KeyHandle 16 4
		parameter_value.d = *(DWORD*)(pUserData + 16);
		inRecord->m_vctParameterList.push_back(parameter_value);

		//KeyName 20 0
		parameter_value.s = (wchar_t*)(pUserData + 20);
		inRecord->m_vctParameterList.push_back(parameter_value);
		pUserData += (wcslen((wchar_t*)(pUserData + 20)) + 1);

		break;
	}
	default:
	{
		inRecord->m_bUseless = true;
		inRecord->m_eventIdentifier.opcode(-1);
		break;
	}
	}
	return;
}

EventRecord* EventRecordManager::ParseVisibleWindowStruct(DWORD processid, DWORD threadid, long long handle,long long left, long long top, long long right, long long bottom, DWORD visible, DWORD toolbar) 
{
	EventRecord* output = new EventRecordVisibleWindow;

	EventIdentifier temp_EventIdentifier(ETWVisibleWindow, 11);

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = threadid;
	output->m_dwProcessId = processid;

	long long data[5] = {handle,left,top,right,bottom};

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 8) {
				//parameter_value.d = *(long long*)(pUserData + ix->second[i].offset);
				parameter_value.d = data[i - 2];
				output->m_vctParameterList.push_back(parameter_value);
			}
			else
				if (ix->second[i].length == 4) {
					//parameter_value.d = *(DWORD*)(pUserData + ix->second[i].offset);
					DWORD value = (i == 0) ? visible : toolbar;
					parameter_value.d = value;
					output->m_vctParameterList.push_back(parameter_value);
				}
		}
	}
	return output;
}

EventRecord*  EventRecordManager::ParseMouseEvent(DWORD processid,long long buttontype){
	EventRecord* output = new EventRecordMouse;

	EventIdentifier temp_EventIdentifier(ETWMouse, 11);

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = 0;
	output->m_dwProcessId = processid;

	long long data[1] = { buttontype%16};
	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 8) {
				//parameter_value.d = *(long long*)(pUserData + ix->second[i].offset);
				parameter_value.d = data[i];
				output->m_vctParameterList.push_back(parameter_value);
				//cout << data[i] << endl;
			}
		}
	}
	return output;
}


EventRecord*  EventRecordManager::ParseKeyboardEvent(DWORD processid, std::wstring value) {
	EventRecord* output = new EventRecordKeyBoard;

	EventIdentifier temp_EventIdentifier(ETWKeyBoard, 11);

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = 0;
	output->m_dwProcessId = processid;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 0) {
				parameter_value.s = value.c_str();
				output->m_vctParameterList.push_back(parameter_value);
			}
		}
	}
	return output;
}
/*
EventRecord* EventRecordManager::ParseRemoveableDeviceEvent(std::wstring value) {
	EventRecord* output = new EventRemovableDevice;

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->time_stamp_ = StartingTime.QuadPart;
	if (!output->init)
		output->init_timecal();
	output->QPCtimeToSystime();

	output->event_identifier_.opcode(EM_AdditionDataEventOPC::DeviceRemoveAble);
	output->event_identifier_.provider_id(ETWAddtionData);
	output->thread_id_ = 0;
	output->process_id_ = 0;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = event_strucp_map.find(output->event_identifier_);
	if (ix != event_strucp_map.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 0) {
				parameter_value.s = value.c_str();
				output->parameter_list_.push_back(parameter_value);
			}
		}
	}
	return output;
}
*/
EventRecord * EventRecordManager::ParseRemoveableDeviceEvent(DWORD serialNum, std::wstring rootPath, std::wstring volumeName, std::wstring fileSystem) {
    EventRecord* output = new EventRemovableDevice;
    EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::DeviceRemoveAble);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = 0;
    output->m_dwProcessId = 0;

    LARGE_INTEGER StartingTime;
    QueryPerformanceCounter(&StartingTime);
    output->m_ulTimeStamp = StartingTime.QuadPart;
    output->QPCtimeToSystime();

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = serialNum;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = rootPath;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = volumeName;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = fileSystem;
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

EventRecord* EventRecordManager::ParseIpconfigEvent(std::string ip) 
{
	EventRecord* output = new EventIpconfig;
	EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::IpconfigInfo);
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = 0;
	output->m_dwProcessId = 0;

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();


	ParameterValue parameter_value;
	parameter_value.s = ToolFunctions::StringToWString(ip);

	output->m_vctParameterList.push_back(parameter_value);
	/*std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = event_strucp_map.find(output->event_identifier_);
	if (ix != event_strucp_map.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 4) {
				parameter_value.d = macro_result;
				output->parameter_list_.push_back(parameter_value);
			}
			else {
				parameter_value.s = filename;
				output->parameter_list_.push_back(parameter_value);
			}
		}
	}*/
	return output;
}

EventRecord* EventRecordManager::ParseExtraEventRecord(PEVENT_RECORD raw_rec)
{
	EventRecord* ev = nullptr;
	switch (raw_rec->EventHeader.ProviderId.Data1)
	{
		case ETWDNSData:
		{
			if (raw_rec->EventHeader.EventDescriptor.Id == EM_DNSDataEventOPC::DNSQueryRequest
				|| raw_rec->EventHeader.EventDescriptor.Id == EM_DNSDataEventOPC::DNSQueryResult)
				ev = new EventRecordDNS(raw_rec);
			break;
		}
		case ETWPowerShell:
		{
			if (raw_rec->EventHeader.EventDescriptor.Id == EM_PowerShellEventOPC::PowerShellScript)
				ev = new EventRecordPowerShell(raw_rec);
			break;
		}
		default:
			break;

	}

	return ev;
}


EventRecord*  EventRecordManager::ParseRansomDetectorEvent(DWORD processid
	, DWORD parentid
	, const std::wstring& processname
	, const std::wstring& parentname
	, const std::wstring& details
	, GUID guid) {
	EventRecord* output = new EventRansomCheck;

	EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::RansomCheck);
	temp_EventIdentifier.event_name("RansomCheck");
	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = 0;
	output->m_dwProcessId = processid;
	ULONG64 s_time = 0;
	output->m_dGuid = guid;

	std::wstring wstrCommandline;
	std::wstring wstrMd5;
	std::wstring wstrProcessPath;
	auto pitr = process_map::g_umapPid2ProcessInfo.find(processid);
	if (pitr != process_map::g_umapPid2ProcessInfo.end())
	{
		s_time = pitr->second.start_QPCtime;
		wstrCommandline = pitr->second.commandline;
		wstrMd5 = pitr->second.md5;
		wstrProcessPath = pitr->second.process_path;

	}

	//long long data[1] = { buttontype % 16 };
	wstring contents[6] = { processname ,parentname ,details ,wstrCommandline ,wstrMd5 ,wstrProcessPath };
	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;

		parameter_value.d = parentid;
		output->m_vctParameterList.push_back(parameter_value);
		for (int i = 0; i < 6; i++)
		{
			parameter_value.s = contents[i];
			output->m_vctParameterList.push_back(parameter_value);
		}
		parameter_value.d = s_time;
		output->m_vctParameterList.push_back(parameter_value);
	}

	return output;
}

EventRecord*  EventRecordManager::ParseRansomTerminateEvent(DWORD processid, const std::wstring& processname, bool terminate, bool stopped, GUID guid) {
	EventRecord* output = new EventRansomTerminate;

	EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::RansomTerminate);
	temp_EventIdentifier.event_name("RansomTerminate");

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = 0;
	output->m_dwProcessId = processid;
	output->m_dGuid = guid;

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;
		parameter_value.d = terminate;
		output->m_vctParameterList.push_back(parameter_value);
		parameter_value.d = stopped;
		output->m_vctParameterList.push_back(parameter_value);
	}
	return output;
}

EventRecord* EventRecordManager::ParsePowershellCheckEvent(powershell_Result ret) {
	EventRecord* output = new EventPowershellCheck;

	EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::PowershellResult);

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
	output->m_dwThreadId = ret.tid;
	output->m_dwProcessId = ret.pid;

	//long long data[1] = { buttontype % 16 };
	//string contents[2] = { ret.verdict,ret.content};
	ParameterValue parameter_value;
	parameter_value.d = ret.score;
	output->m_vctParameterList.push_back(parameter_value);
	ParameterValue parameter_value1;
	parameter_value1.s= ToolFunctions::Str2Wstr(ret.content);
	output->m_vctParameterList.push_back(parameter_value1);
	ParameterValue parameter_value2;
	parameter_value2.s = ToolFunctions::Str2Wstr(ret.command);
	output->m_vctParameterList.push_back(parameter_value2);
	return output;
}
EventRecord* EventRecordManager::ParseSecurityEventRecord(std::wstring raw_rec, long pid, long tid) {

	EventRecord* output = new EventRecordSecurity;

	EventIdentifier temp_EventIdentifier(EVTSecurity, 10);

	LARGE_INTEGER StartingTime;
	QueryPerformanceCounter(&StartingTime);
	output->m_ulTimeStamp = StartingTime.QuadPart;
	output->QPCtimeToSystime();
	output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwProcessId = pid;
	output->m_dwThreadId = tid;	

	//long long data[5] = { handle,left,top,right,bottom };

	std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
	if (ix != m_mapEventStrucp.end()) {
		ParameterValue parameter_value;
		for (int i = 0; i != ix->second.size(); i++) {
			if (ix->second[i].length == 0) {
				//parameter_value.d = *(long long*)(pUserData + ix->second[i].offset);
				parameter_value.s = raw_rec;
				output->m_vctParameterList.push_back(parameter_value);
			}
		}
	}
	return output;
}

EventRecord * EventRecordManager::ParseZoneIdentifierEvent(ULONG64 time_stamp, DWORD processid, DWORD zoneId, wstring referrerUrl, std::wstring hostUrl, std::wstring fileName)
{
    EventRecord* output = new EventRemovableDevice;
    EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::ZoneIdentifier);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = 0;
    output->m_dwProcessId = processid;

    output->m_ulTimeStamp = time_stamp;
    //output->QPCtimeToSystime();

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = processid;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.d = zoneId;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = referrerUrl;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = hostUrl;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = fileName;
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

EventRecord * EventRecordManager::ParseRuleIdentifierEvent(EventRecord * ev, SRule srule) 
{
    if (!ev)
    {
        return nullptr;
    }
    EventRecord* output = new EventRemovableDevice;
    EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::RuleIdentifier);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = 0;
    output->m_dwProcessId = ev->get_process_id_();

    output->m_ulTimeStamp = ev->m_ulTimeStamp;
   // output->QPCtimeToSystime();

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = srule.rule_id;       
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(Filter::GetEventName(ev->m_eventIdentifier));
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = public_json_interface::GetInstance().GetEventArguments(ev);
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

EventRecord * EventRecordManager::ParseSysmonDriverLoadedEvent(SDriverLoaded sdl) 
{
    EventRecord* output = new EventDriverLoaded;
    EventIdentifier temp_EventIdentifier(EVTSysmon, EM_SysmonEventOPC::Drive_Loaded);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = 0;
    output->m_dwProcessId = 0;

    LARGE_INTEGER StartingTime;
    QueryPerformanceCounter(&StartingTime);
    output->m_ulTimeStamp = StartingTime.QuadPart;
    output->QPCtimeToSystime();

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = sdl.Signed;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(sdl.Signature);
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(sdl.SignatureStatus);
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(sdl.ImageLoaded);
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(sdl.Hashes);
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

EventRecord * EventRecordManager::ParseSysmonProcessAccessEvent(SProcessAccess spa) 
{
    if (!Filter::GetInstance().FilterBeforeRecInstance(EVTSysmon, EM_SysmonEventOPC::Process_Access, spa.SourceProcessId))
        return nullptr;
    if (Filter::GetInstance().query_process_id_black_list(spa.SourceProcessId))
        return nullptr;

    EventRecord* output = new EventProcessAccess;
    EventIdentifier temp_EventIdentifier(EVTSysmon, EM_SysmonEventOPC::Process_Access);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = spa.SourceThreadId;
    output->m_dwProcessId = spa.SourceProcessId;

    LARGE_INTEGER StartingTime;
    QueryPerformanceCounter(&StartingTime);
    output->m_ulTimeStamp = StartingTime.QuadPart;
    output->QPCtimeToSystime();

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = spa.TargetProcessId;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.d = spa.SourceProcessId;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.d = spa.GrantedAccess;
        output->m_vctParameterList.push_back(parameter_value);       
        parameter_value.s = ToolFunctions::StringToWString(spa.TargetImage);
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ToolFunctions::StringToWString(spa.SourceImage);
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

EventRecord * EventRecordManager::ParseHashInfoEvent(EventRecord * ev, std::wstring md5, long fileSize)
{
    if (!ev) {
        return nullptr;
    }
    EventRecord* output = new EventHashInfo;
    EventIdentifier temp_EventIdentifier(ETWAddtionData, EM_AdditionDataEventOPC::HashInfo);
    output->m_eventIdentifier = temp_EventIdentifier;
    output->m_dwThreadId = 0;
	DWORD pid = ev->get_process_id_();
	output->m_dwProcessId = pid;

	process_map::g_umapPid2ProcessInfo[pid].md5 = md5;
    
	output->m_ulTimeStamp = ev->m_ulTimeStamp;    

    std::map<EventIdentifier, std::vector<EventParameter>>::iterator ix = m_mapEventStrucp.find(output->m_eventIdentifier);
    if (ix != m_mapEventStrucp.end()) {
        ParameterValue parameter_value;
        parameter_value.d = pid;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.d = fileSize;
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = ev->GetStringParameter(parameter_index_enum::FileName);
        output->m_vctParameterList.push_back(parameter_value);
        parameter_value.s = md5;
        output->m_vctParameterList.push_back(parameter_value);
    }
    return output;
}

void EventRecordManager::_InitEventStructMap(const String& file_name)
{
	int_32 property_num;
	String event_name;
	int_64 guid;
	int_32 opcode;
	EventIdentifier temp_identifier;
	EventParameter temp_parameter;
#ifdef USE_RAW_FORMAT
	std::fstream infile(file_name);
#else
	std::fstream infile(file_name, ios::in | ios::binary);
#endif // USE_RAW_FORMAT;
	if (!infile)
	{
		WriteLog4cPlusA(ERROR_LEVEL, "EventRecordManager::_InitEventStructMap: %s not exists\n", file_name.c_str());
	}
	try
	{
#ifdef USE_RAW_FORMAT

		while (!infile.eof())
		{
			infile >> guid; //providerID
			infile >> opcode;
			infile >> event_name;
			temp_identifier.opcode(opcode);
			temp_identifier.provider_id((uint_32)guid);
			temp_identifier.event_name(event_name);
			infile >> property_num;
			Filter::AddEvent(temp_identifier);
			for (int j = 0; j != property_num; j++)
			{
				std::string parameter_mame;
				infile >> parameter_mame;
				m_parameterPosition[m_providerModuloMappingHash[guid & 0xff]][opcode % g_nKOpcodeNum][(parameter_index_enum)m_baseParameterIndex.get_parameter_string_vector(parameter_mame)] = j;
				temp_parameter.name = m_baseParameterIndex.get_parameter_string_vector(parameter_mame);
				infile >> temp_parameter.offset;
				infile >> temp_parameter.length;
				m_mapEventStrucp[temp_identifier].push_back(temp_parameter);
			}
		}

#else

		String line_str;
		while (getline(infile, line_str))
		{
			STRING_VECTOR info_vector;
			StringUtil::split(ToolFunctions::DecryptStr(line_str), ' ', info_vector);
			guid = StringUtil::ParseInt64(info_vector[0]);
			opcode = StringUtil::ParseInt32(info_vector[1]);
			event_name = info_vector[2];
			temp_identifier.opcode(opcode);
			temp_identifier.provider_id((uint_32)guid);
			temp_identifier.event_name(event_name);
			Filter::AddEvent(temp_identifier);

			String read_str;
			getline(infile, read_str);
			property_num = StringUtil::ParseInt32(ToolFunctions::DecryptStr(read_str));

			STRING_VECTOR param_vector;
			for (int_32 i = 0; i < property_num; ++i)
			{
				param_vector.clear();

				getline(infile, read_str);
				StringUtil::split(ToolFunctions::DecryptStr(read_str), ' ', param_vector);
				String param_name = param_vector[0];
				temp_parameter.offset = StringUtil::ParseInt32(param_vector[1]);
				temp_parameter.length = StringUtil::ParseInt32(param_vector[2]);

				m_parameterPosition[m_providerModuloMappingHash[guid & 0xff]][opcode % g_nKOpcodeNum][(parameter_index_enum)m_baseParameterIndex.get_parameter_string_vector(param_name)] = i;
				temp_parameter.name = m_baseParameterIndex.get_parameter_string_vector(param_name);
				m_mapEventStrucp[temp_identifier].push_back(temp_parameter);
			}
		}

#endif // USE_RAW_FORMAT;

		infile.close();
	}
	catch (...)
	{
		WriteLog4cPlusA(ERROR_LEVEL, "EventRecordManager::_InitEventStructMap: init by %s failed!\n", file_name.c_str());
	}
}

bool EventRecordManager::_ConvertSidtoUname(PVOID sid, std::wstring& uname)
{
	bool ret = false;

	std::wstring strSid;
	LPWSTR* chSID = new LPWSTR;
	if (ConvertSidToStringSid(sid, chSID))
	{
		strSid = (wchar_t*)*chSID;
	}
	else
		WriteLog4cPlus(ERROR_LEVEL, L"EventRecordManager::ConvertSidToStringSid failed errorcode: %d", GetLastError());

	if (m_umapSid2Uname.count(strSid))
	{
		uname = m_umapSid2Uname[strSid];
		if (chSID)	{ delete chSID; chSID = nullptr; }
		return true;
	}
	
	wchar_t* cchName = new wchar_t[MAX_PATH * 2];
	wchar_t* cchDomain = new wchar_t[MAX_PATH * 2];
	DWORD nSize = MAX_PATH, dSize = MAX_PATH;
	SID_NAME_USE Type = SidTypeUser;
	ret = LookupAccountSid(NULL, sid, cchName, &nSize, cchDomain, &dSize, &Type);
	if (ret)
	{
		wcscat_s(cchDomain, MAX_PATH * 2, L"\\");
		wcscat_s(cchDomain, MAX_PATH * 2, cchName);
		uname = cchDomain;
		m_umapSid2Uname.insert(make_pair(strSid, uname));
	}
	else
	{
		WriteLog4cPlus(ERROR_LEVEL, L"EventRecordManager::_ConvertSidtoUname failed errorcode: %d", GetLastError());
	}

	if (chSID) { delete chSID; chSID = nullptr; }
	if (cchName) { delete[] cchName; cchName = nullptr; }
	if (cchDomain) { delete[] cchDomain; cchDomain = nullptr; }
  
	return ret;
}
