#include "stdafx.h"
#include "thread_task_cerficate_image.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "event_record_subclass.h"
#include "concurrent_queue.h"

CertificateImageThreadTask::CertificateImageThreadTask()
	: BaseThreadTask(CERTIFICATE_IMAGE_TASK_MODE)
{
	
}

CertificateImageThreadTask::~CertificateImageThreadTask()
{

}

void CertificateImageThreadTask::_Excute()
{
	//_certificate_dataqueue will change in class outside,so dont use Iterator to avoid crash; to fix chips;
	//Sleep(MS_ONE_SECOND * 2); // wait 2s to make cpu express better;

	while (!_stop_flag) 
	{
		if (!m_queueCertificateData.empty())
		{
			EventRecord* event_record = nullptr;
			bool flag = m_queueCertificateData.front_pop(event_record);
			if (!flag) 
				continue;

			EventRecordImage* image_record = dynamic_cast<EventRecordImage*>(event_record);
			if (image_record)
			{
				image_record->certificate();
				InitCollector::GetCollector()->PushSendRecord(image_record);
			}
			else
			{
				WriteLog4cPlus(ERROR_LEVEL, L"CertificateImageThreadTask::_Excute: wrong type record");
				SAFE_DELETE(event_record);
			}

			{
				std::wstring& file_name = image_record->GetStringParameter(parameter_index_enum::FileName);

				m_lockProcessingFiles.WriteLock();
				m_setProcessingFileNames.erase(file_name);
				auto iter_f = m_mapProcessingFileLists.find(file_name);
				if (iter_f != m_mapProcessingFileLists.end())
				{
					const auto& file_list = iter_f->second;
					for (EventRecordImage* image_rec : file_list)
					{
						image_rec->certificate();
						InitCollector::GetCollector()->PushSendRecord(image_rec);
					}

					m_mapProcessingFileLists.erase(iter_f);
				}
				m_lockProcessingFiles.WriteUnlock();
			}

			if (m_queueCertificateData.size() < 100)
			{
				Sleep(25);
			}
			else {
				Sleep(10);
			}
		}
		else 
		{
			m_signal.Wait();
		}
	}
}

void CertificateImageThreadTask::Log()
{
	int size = m_queueCertificateData.size();
#ifdef OUTPUT_COMMAND_LINE       
	cout <<"CertificateImageThreadTask::Log:certificate_data_queue size is " << size << endl;
#endif // OUTPUT_COMMAND_LINE;
	WriteLog4cPlus(INFO_LEVEL, L"CertificateImageThreadTask::Log:certificate_data_queue size is %d", size);
}

void CertificateImageThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitImageCerificate");
}

void CertificateImageThreadTask::Stop()
{
	_stop_flag = true;
	m_signal.NotifyOne();
	if (_thread.joinable())
	{
		_thread.join();
	}
}

void CertificateImageThreadTask::AddData(EventRecord* record)
{
	EventRecordImage* image_rec = dynamic_cast<EventRecordImage*>(record);
	if (!image_rec)
	{
		SAFE_DELETE(record);
		return;
	}
	
	m_lockProcessingFiles.WriteLock();
	const std::wstring& file_name = record->GetStringParameter(parameter_index_enum::FileName);
	int nfile_pid = record->get_process_id_();
	std::wostringstream wsPid;
	wsPid << nfile_pid;
	std::wstring wsFile_Inf = wsPid.str() + L"_" + file_name;
//#ifdef ETW_FILTER_TEST
//	std::string strName = CPykMgrTemplate<CP_ACP>(file_name.c_str());
//	char szTemp[50] = { 0 };
//	StringHelp::StringFormatA(szTemp, 50, "%d,%d,%d,%d,%d,"
//		, 1
//		, 1
//		, 1
//		, 1
//		, 1);
//	std::string strT = szTemp;
//	strT += "AddData:  ";
//	strT += strName;
//	g_thCRC.AddLine("add", strT.c_str());
//#endif // ETW_FILTER_TEST
	LONG64 m_ulTimeStamp = (LONG64)record->get_time_stamp_()/1000000;

	if (m_setProcessingFileNames.find(wsFile_Inf) != m_setProcessingFileNames.end())
	{
		if(m_mapProcessingFileTimes.find(wsFile_Inf) != m_mapProcessingFileTimes.end())
		{
			LONG64 time = m_mapProcessingFileTimes[wsFile_Inf];
			if (abs(time - m_ulTimeStamp) > 100)
			{
				m_mapProcessingFileLists[wsFile_Inf].push_back(image_rec);
				m_mapProcessingFileTimes[wsFile_Inf] = m_ulTimeStamp;
			}
		}
		else
		{
			m_mapProcessingFileLists[wsFile_Inf].push_back(image_rec);
			m_mapProcessingFileTimes[wsFile_Inf] = m_ulTimeStamp;
		}
	}
	else
	{
		m_setProcessingFileNames.insert(wsFile_Inf);
		if (m_mapProcessingFileTimes.find(wsFile_Inf) != m_mapProcessingFileTimes.end())
		{
			LONG64 time = m_mapProcessingFileTimes[wsFile_Inf];
			if (abs(time - m_ulTimeStamp) > 100)
			{
				m_mapProcessingFileTimes[wsFile_Inf] = m_ulTimeStamp;
				m_queueCertificateData.push(record);
				m_signal.NotifyOne();
			}
		}
		else
		{
			m_mapProcessingFileTimes[wsFile_Inf] = m_ulTimeStamp;
			m_queueCertificateData.push(record);
			m_signal.NotifyOne();
		}		
	}
	m_lockProcessingFiles.WriteUnlock();
}

