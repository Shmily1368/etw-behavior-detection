#pragma once
#include <Shlwapi.h>
#include "StringHelp.h"
#include <vector>
#include "MemoryFileHelper.h"
#include <time.h>
#include "TH_TimeStampHelper.h"

//输出信息到dbgview
#define OUTPUT_DBGVIEW

class CTHCsvRecordConfig
{
	friend class CTHCsvRecordConfig_ETW;
	//秒级
	inline time_t SystemTimeToTime_t(const SYSTEMTIME& st)
	{
		tm temptm = { st.wSecond,st.wMinute,st.wHour,st.wDay,st.wMonth - 1,st.wYear - 1900,st.wDayOfWeek,0,0 };
		return mktime(&temptm);
	}
public:
	CTHCsvRecordConfig(LPCTSTR lpRecordFileName = nullptr):
		m_memFileHelper(nullptr)
		, m_bIsFirst(true)
		, m_bDefaultInit(false)
	{
		if (m_bDefaultInit)
		{
			Init(lpRecordFileName);

			if (m_bIsFirst)
			{
				m_vctTitleList.push_back("Time");
				m_vctTitleList.push_back("TimeStamp");
				m_vctTitleList.push_back("Tag");
				//之后添加额外列名
				m_vctTitleList.push_back("Data");

				InitCsv();
			}
		}		
		InitializeCriticalSection(&m_cs);
	}
	
	~CTHCsvRecordConfig()
	{
		DeleteCriticalSection(&m_cs);
	}

	void AddLine(LPCSTR lpTime,LPCSTR lpTimeStamp,LPCSTR lpTag,LPCSTR lpData)
	{		
		std::string strData = lpTime;
		strData += ",";
		strData += lpTimeStamp;
		strData += ",";
		strData += lpTag;
		strData += ",";
		strData += lpData;
		strData += "\n";
#ifdef OUTPUT_DBGVIEW
		OutputDebugStringA(strData.c_str());
#endif // OUTPUT_DBGVIEW
		EnterCriticalSection(&m_cs);
		m_memFileHelper->AppendData(strData.c_str(), (const DWORD)strData.length());
		LeaveCriticalSection(&m_cs);
	}

	void AddLine( LPCSTR lpTag, LPCSTR lpData)
	{
		char szNow[MAX_PATH] = { 0 };
		char szNowTimeStamp[MAX_PATH] = { 0 };
		SYSTEMTIME sysTime;
		GetLocalTime(&sysTime);
		StringHelp::StringFormatA(szNow, MAX_PATH, "%04d-%02d-%02d %02d:%02d:%02d"
			, sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
		CHighResolutionTimeStampHelper hrtsh;
		StringHelp::StringFormatA(szNowTimeStamp, MAX_PATH, "%d"
			, hrtsh.GetCurrentTimeStamp());
		AddLine(szNow, szNowTimeStamp, lpTag, lpData);
	}

	void AddLineFormat(LPCSTR lpTag,const char* _Format, ...)
	{
		va_list arglist;
		char szOut[OUT_SIZE] = { 0 };
		va_start(arglist, _Format);
		_vsprintf_s_l(szOut, OUT_SIZE, _Format, NULL, arglist);
#ifdef OUTPUT_DBGVIEW
		OutputDebugStringA(szOut);
#endif // OUTPUT_DBGVIEW
		AddLine(lpTag, szOut);
		va_end(arglist);
	}

private:
	std::wstring m_strConfigPath;
	std::vector<std::string> m_vctTitleList;
	bool m_bIsFirst;
	CMemoryFileHelper* m_memFileHelper;
	bool m_bDefaultInit;
	CRITICAL_SECTION m_cs;

	void Init(LPCTSTR lpRecordFileName = nullptr)
	{
		TCHAR szPath[4096 + 1] = { 0 };
		GetModuleFileName(NULL, szPath, 4096);
		if (lpRecordFileName)
			_tcscat_s(szPath, lpRecordFileName);
		else
			_tcscat_s(szPath, L"THCsvRecordConfig.csv");
		m_strConfigPath = szPath;
		OutputDebugString(m_strConfigPath.c_str());
		m_bIsFirst = !PathFileExists(m_strConfigPath.c_str());
		m_memFileHelper = new CMemoryFileHelper(szPath);
		m_memFileHelper->InitFileMemory();
	}

	void InitCsv()
	{
		std::string strData;
		auto i = m_vctTitleList.begin();
		strData += *i;
		for (i++; i != m_vctTitleList.end(); i++)
		{
			strData += ",";
			strData += *i;
		}
		strData += "\n";
#ifdef OUTPUT_DBGVIEW
		OutputDebugStringA(strData.c_str());
#endif // OUTPUT_DBGVIEW
		m_memFileHelper->AppendData(strData.c_str(), (const DWORD)strData.length());
	}
};

class CTHCsvRecordConfig_ETW:public::CTHCsvRecordConfig
{
public:
	CTHCsvRecordConfig_ETW(LPCTSTR lpRecordFileName = nullptr)
	{
		Init(lpRecordFileName);

		if (m_bIsFirst)
		{
			m_vctTitleList.push_back("Time");
			m_vctTitleList.push_back("TimeStamp");
			m_vctTitleList.push_back("Tag");

			//m_vctTitleList.push_back("EventHeader.Flags");
			//m_vctTitleList.push_back("EventHeader.ProviderId.Data1");
			//m_vctTitleList.push_back("TYPE");
			//m_vctTitleList.push_back("SUBTYPE");
			//m_vctTitleList.push_back("EventHeader.EventDescriptor.Opcode");		
			//m_vctTitleList.push_back("EventHeader.EventDescriptor.Id");
			//m_vctTitleList.push_back("EventHeader.ThreadId");
			//m_vctTitleList.push_back("EventHeader.ProcessId");
			//m_vctTitleList.push_back("EventHeader.TimeStamp.QuadPart");
			//m_vctTitleList.push_back("EventHeader.EventHeader.ProviderId");

			m_vctTitleList.push_back("pid");
			m_vctTitleList.push_back("path");
			m_vctTitleList.push_back("startTime");
			m_vctTitleList.push_back("isalive");
			m_vctTitleList.push_back("parentPid");
			m_vctTitleList.push_back("parentName");

			m_vctTitleList.push_back("pid");
			m_vctTitleList.push_back("process_name");
			m_vctTitleList.push_back("ppid");
			m_vctTitleList.push_back("pprocess_name");
			m_vctTitleList.push_back("write_c");
			m_vctTitleList.push_back("delete_c");
			m_vctTitleList.push_back("dir_enum_c");
			m_vctTitleList.push_back("read_c");
			m_vctTitleList.push_back("rename_c");
			m_vctTitleList.push_back("overwrite_c");
			m_vctTitleList.push_back("file_magic_number_change");
			m_vctTitleList.push_back("file_magic_number_change_v");
			m_vctTitleList.push_back("file_similarity");
			m_vctTitleList.push_back("file_similarity_v");
			m_vctTitleList.push_back("file_type_r_table");
			m_vctTitleList.push_back("file_type_w_table");
			m_vctTitleList.push_back("file_type_r_c");
			m_vctTitleList.push_back("file_type_w_c");
			m_vctTitleList.push_back("action_interpretation");
			m_vctTitleList.push_back("action_path_interpretation");
			m_vctTitleList.push_back("irp2");
			m_vctTitleList.push_back("irp3");
			m_vctTitleList.push_back("path_hash_table");
			m_vctTitleList.push_back("path_c");
			m_vctTitleList.push_back("file_c");
			m_vctTitleList.push_back("regcreate_c");
			m_vctTitleList.push_back("regdelete_c");
			m_vctTitleList.push_back("regquery_c");
			m_vctTitleList.push_back("regset_c");
			m_vctTitleList.push_back("encryptdll_c");
			m_vctTitleList.push_back("apis_c");
			m_vctTitleList.push_back("file_size_change0");
			m_vctTitleList.push_back("file_size_change1");
			m_vctTitleList.push_back("file_size_change");
			m_vctTitleList.push_back("string");
			InitCsv();
		}
	}
	~CTHCsvRecordConfig_ETW(){}

private:

};