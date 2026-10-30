#include "stdafx.h"
#include "tool_functions.h"
#include "output_ransom.h"
#include "event_record_subclass.h"
#include "event_record_callstack.h"
#include "init_collector.h"
#include "time_util.h"
#include "event_record_manager.h"
#include "parameter_index.h"
#include "filter.h"
#include <Windows.h>
#include <Shlwapi.h>
#pragma comment(lib,"shlwapi.lib")

set< uint_32> OutputRansom::m_setOpcodeOutput = { 1,2,3,64,67,68,71,70,72,65 };
//const STRING_VECTOR ransomapis
//{
//	"CryptImportKey",
//	"CryptDecrypt",
//	"CryptDeriveKey",
//	"GetUserName",
//	"CryptGenKey",
//	"CryptDecodeObject",
//	"CryptImportPublicKeyInfo",
//	"NdrClientCall2",
//	"InternetOpen",
//	"Socket",
//};

OutputRansom::OutputRansom()
{
	WCHAR current_path[MAX_PATH] = { 0 };
	GetCurrentDirectory(_countof(current_path), current_path);
	wstring path(current_path);
	if (Setting::GetInstance().enable_ransom_output())
	{
		wstring _randomoutputdir = path + L"\\output";
		if (!PathFileExists(_randomoutputdir.c_str()))
		{
			CreateDirectory(_randomoutputdir.c_str(), NULL);
		}
	}
	
	// 启动ransom模块线程
	m_threadRansom = std::thread(&OutputRansom::_ExcuteRansomDetector, this);
	m_threadRansom.detach();
	m_tInitTime = time(NULL);
    m_strUserPath = ToolFunctions::GetUserPath();
	WriteLog4cPlusA(INFO_LEVEL, "InitOutputRansom user_path %s", m_strUserPath.c_str());

	EventRecordStaticInit::InitEventRecordSubclassStatic();
}

OutputRansom::~OutputRansom()
{

}

bool OutputRansom::OutputEventRecord(EventRecord* rec)
{
	if (!rec)	return false;
	// 10min清理map
	auto times = time(NULL);
	if (time(NULL) - m_tInitTime > m_tCleanTimeThreshold)
	{
		m_tInitTime = time(NULL);
		_CleanUselessCache();
	}

	if (Filter::GetInstance().IsRansomBlackProcess(rec))
		_RansomParse(rec);

	return true;
}

void OutputRansom::_ExcuteRansomDetector()
{
	RansomDetector::GetInstance().Init();
}

void OutputRansom::_PushRansomRecord(EventRecord * record)
{
	if (!record)
		return;

	auto provider_id = record->get_event_identifier_().provider_id();
	auto opcode_id = record->get_event_identifier_().opcode();
	if (provider_id != ETWStackWalk && provider_id != ETWFileIo && provider_id != ETWProcess)
		return;
	if (provider_id != ETWStackWalk && m_setOpcodeOutput.find(opcode_id) == m_setOpcodeOutput.end())
		return;

	// 推送ransom模块
	event ev(*record);

	/*if (ev.EventName == "ProcessStart")
		std::cout << "position : _PushRansomRecord " << " PID: " << ev.arguments.ProcessId << " FileName: " << ev.arguments.ImageFileName << std::endl;*/

	RansomDetector::GetInstance().PushRansomRecord(ev);
	m_nOutputEventSum++;
	if (m_nOutputEventSum % 20000 == 0) {
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_PushRansomRecord sum: " << m_nOutputEventSum << 
			" fileioread_cache_map:" << m_umapFileioReadCache.size()<<
			" fileiowrite_cache_map:"<< m_umapFileioWriteCache .size()<< endl;
 #endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"_PushRansomRecord counts: %d  fileioread_cache_map size: %d fileiowrite_cache_map size: %d", m_nOutputEventSum,
			m_umapFileioReadCache.size(), m_umapFileioWriteCache.size());
	}
}

void OutputRansom::_RansomParse(EventRecord* rec)
{
	auto event_providerid = rec->get_event_identifier_().provider_id();
	auto event_opcode = rec->get_event_identifier_().opcode();
	if (event_providerid == ETWFileIo)
	{
        // add by zxw on 20201112       
        if (event_opcode == EM_FileioEventOPC::FileioCreateEvent)
        {
            auto open_path = rec->GetStringParameter(parameter_index_enum::OpenPath);
			if (open_path.size() != 0)
			{
				if (!ToolFunctions::JudgePath(m_strUserPath, ToolFunctions::WStringToString(open_path)))
					return;
				//size_t end = open_path.find_last_of(L'.');
				//if (end != string::npos)
				//{
				//	auto suffix = ToolFunctions::WStringToString(open_path.substr(end + 1));//获取文件后缀
				//	if (suffix != "" && !Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				//		return;
				//}
			}
        }
        else {
			//这个else很少命中？
            auto file_name = rec->GetStringParameter(parameter_index_enum::FileName);
			if (file_name.size() != 0)
			{
				if (!ToolFunctions::JudgePath(m_strUserPath, ToolFunctions::WStringToString(file_name)))
					return;
				//size_t end = file_name.find_last_of(L'.');
				//if (end != string::npos)
				//{
				//	auto suffix = ToolFunctions::WStringToString(file_name.substr(end + 1));//获取文件后缀
				//	if (suffix != "" && !Filter::query_ransom_suffix_white_list(StringUtil::ToLowerCase(suffix)))
				//		return;
				//}
			}            
        }        
        //

		switch (event_opcode)
		{
		case EM_FileioEventOPC::FileIoCleanup:
		{         
			_RansomFileIoCleanup(rec);
			break;
		}
		case EM_FileioEventOPC::FileIoRead:
		{
			_RansomFileIoRead(rec);
			break;
		}
		case EM_FileioEventOPC::FileIoWirte:
		{          
			_RansomFileIoWirte(rec);
			break;
		}		
		default:
		{            
			_PushRansomRecord(rec);
			break;
		}
		}
	}
	else if (event_providerid == ETWProcess)
	{
		// 清理缓存
		_CleanProcessCache(rec->get_process_id_());

		switch (event_opcode)
		{
		case EM_ProcessEventOPC::ProcessStart:
		case EM_ProcessEventOPC::ProcessEnd:
		case EM_ProcessEventOPC::ProcessDCStart:
		{
//#ifdef ETW_EVENT_RECORD_TEST	
//			rec->Record2csv("_RansomParse");
//#endif
			_PushRansomRecord(rec);
			break;
		}
		default:
			break;
		}
	}
	else if (event_providerid == ETWStackWalk)
	{
		_PushRansomRecord(rec);
	}
}

void OutputRansom::_RansomFileIoRead(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (process_id == 0 || fileobj == 0)
		return;
	event ev(*rec);
	ev.set_time_stamp(time(NULL));
	auto iter = m_umapFileioReadCache.find(process_id);
	if (iter != m_umapFileioReadCache.end())
	{
		auto& cache_set = iter->second;
		auto cashe_iter = cache_set.find(fileobj);
		if (cashe_iter != cache_set.end())
		{
			cashe_iter->second = ev;
		}else
			cache_set.insert(make_pair(fileobj, ev));		
	}
	else
	{	
		m_umapFileioReadCache[process_id].insert({fileobj, ev});
	}
}

void OutputRansom::_RansomFileIoWirte(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (process_id == 0 || fileobj == 0)
		return;
	event ev(*rec);
	ev.set_time_stamp(time(NULL));
	auto iter = m_umapFileioWriteCache.find(process_id);
	if (iter != m_umapFileioWriteCache.end())
	{
		auto& cache_set = iter->second;
		auto cashe_iter = cache_set.find(fileobj);
		if (cashe_iter != cache_set.end())
		{
			auto& record = cashe_iter->second;
			// 累加IoSize
			if (record.arguments.Offset != rec->GetDataParameter(parameter_index_enum::Offset))
			{
				record.arguments.IoSize += rec->GetDataParameter(parameter_index_enum::IoSize);
				record.set_time_stamp(time(NULL));
			}
		}
		else
			cache_set.insert(make_pair(fileobj, ev));
	}
	else
	{
		m_umapFileioWriteCache[process_id].insert({ fileobj, ev });		
	}
}

void OutputRansom::_RansomFileIoCleanup(EventRecord* rec)
{
	auto process_id = rec->get_process_id_();
	auto fileobj = rec->GetDataParameter(parameter_index_enum::FileObject);
	if (fileobj == 0)
		return;

	auto iterr = m_umapFileioReadCache.find(process_id);
	if (iterr != m_umapFileioReadCache.end())
	{
		auto& cache_set = iterr->second;
		auto cache_iterr = cache_set.find(fileobj);
		if (cache_iterr != cache_set.end())
		{
			// 推送本地ransom
			RansomDetector::GetInstance().PushRansomRecord(cache_iterr->second);
			cache_set.erase(cache_iterr);
		}		
	}

	auto iterw = m_umapFileioWriteCache.find(process_id);
	if (iterw != m_umapFileioWriteCache.end())
	{
		auto& cache_set = iterw->second;
		auto cache_iterr = cache_set.find(fileobj);
		if (cache_iterr != cache_set.end())
		{
			// 推送本地ransom
			RansomDetector::GetInstance().PushRansomRecord(cache_iterr->second);
			cache_set.erase(cache_iterr);
		}
	}
	// cleanup事件推送ransom
	_PushRansomRecord(rec);
}

void OutputRansom::_RansomCleanMap()
{
	if (m_umapFileioReadCache.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map size: " << m_umapFileioReadCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileioread_cache_map size: %d", m_umapFileioReadCache.size());

		std::unordered_map<DWORD, std::unordered_map<ULONG64, event>>().swap(m_umapFileioReadCache);
	}

	if (m_umapFileioWriteCache.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map size: " << m_umapFileioWriteCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileiowrite_cache_map size: %d", m_umapFileioWriteCache.size());

		std::unordered_map<DWORD, std::unordered_map<ULONG64, event>>().swap(m_umapFileioWriteCache);
	}
}

void OutputRansom::_CleanUselessCache()
{
	if (m_umapFileioReadCache.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map size: " << m_umapFileioReadCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileioread_cache_map size: %d", m_umapFileioReadCache.size());
		for (auto iter = m_umapFileioReadCache.begin(); iter != m_umapFileioReadCache.end();)
		{
			auto& cash_set = iter->second;
			for (auto iterr = cash_set.begin(); iterr != cash_set.end();)
			{
				if (time(NULL) - iterr->second.get_time_stamp() > m_tCleanTimeThreshold)
				{
					iterr = cash_set.erase(iterr);
				}
				else
					iterr++;
			}
			//
			if (cash_set.size() > 0)
			{				
				WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap _fileioread_cache_map fileobject: %d  size: %d", iter->first, cash_set.size());
				iter++;
			}
			else
				iter = m_umapFileioReadCache.erase(iter);
		}
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileioread_cache_map over size: %d", m_umapFileioReadCache.size());
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileioread_cache_map over size: " << m_umapFileioReadCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
	}

	if (m_umapFileioWriteCache.size() > 0)
	{
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map size: " << m_umapFileioWriteCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileiowrite_cache_map size: %d", m_umapFileioWriteCache.size());

		for (auto iter = m_umapFileioWriteCache.begin(); iter != m_umapFileioWriteCache.end();)
		{
			auto& cash_set = iter->second;
			for (auto iterw = cash_set.begin(); iterw != cash_set.end();)
			{
				if (time(NULL) - iterw->second.get_time_stamp() > m_tCleanTimeThreshold)
				{
					iterw = cash_set.erase(iterw);
				}
				else
					iterw++;
			}
			//
			if (cash_set.size() > 0)
			{
				WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap _fileiowrite_cache_map fileobject: %d size: %d", iter->first, cash_set.size());
				iter++;
			}
			else
				iter = m_umapFileioWriteCache.erase(iter);
		}
		WriteLog4cPlus(INFO_LEVEL, L"_RansomCleanMap fileiowrite_cache_map over size: %d", m_umapFileioWriteCache.size());
#ifdef OUTPUT_COMMAND_LINE       
		cout << "_RansomCleanMap fileiowrite_cache_map over size: " << m_umapFileioWriteCache.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
	}
}

void OutputRansom::_CleanProcessCache(DWORD process_id)
{
	m_umapFileioReadCache.erase(process_id);
	m_umapFileioWriteCache.erase(process_id);
}
