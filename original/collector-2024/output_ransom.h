/********************************************************************
	Created:		2019-11-28
	Author:			zxw;
	Version:		1.0.0(version);
	Description:	output ransom;
----------------------------------------------------------------------------
***********************************************************************/
#pragma once
#include "event_record.h"
#include "output.h"
#include <stdio.h>
#include "RansomDetector.h"

using namespace std;

class OutputRansom : public Output
{
public:
	OutputRansom();
	~OutputRansom();
	virtual bool OutputEventRecord(EventRecord* rec) override;
	virtual void DataCompress(EventRecords* rec, String* data_str) override { }	
	virtual void Clean() 
	{
		
	};

private:
	void _ExcuteRansomDetector();
	void _PushRansomRecord(EventRecord* record);	
	void _RansomParse(EventRecord* rec);
	void _RansomFileIoRead(EventRecord* rec);
	void _RansomFileIoWirte(EventRecord* rec);
	void _RansomFileIoCleanup(EventRecord* rec);
	void _RansomCleanMap();						// 清理缓存
	void _CleanUselessCache();					// 定时清理无效缓存信息
	void _CleanProcessCache(DWORD process_id);	// 
private:
	unsigned int m_nOutputEventSum = 0;
	std::thread m_threadRansom;
	// 缓存文件操作事件<process_id,<fileobject,event>>
	std::unordered_map<DWORD, std::unordered_map<ULONG64, event>> m_umapFileioReadCache;
	std::unordered_map<DWORD, std::unordered_map<ULONG64, event>> m_umapFileioWriteCache;
	//std::unordered_map<ULONG64, event> fileioread_cache_map;
	//std::unordered_map<ULONG64, event> fileiowrite_cache_map;
	//
	const time_t m_tCleanTimeThreshold = 10*60;	// 10min
	time_t m_tInitTime;
    std::string m_strUserPath;
	static set< uint_32> m_setOpcodeOutput ;
};

