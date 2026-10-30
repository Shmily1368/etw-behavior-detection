/********************************************************************
	Created:		2019-01-07
	Author:			chips;
	Version:		1.0.0(版本号);
	Description:	初始化采集器的类;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  unknown    |	0.1.0	 |	unknown		  | Create file
----------------------------------------------------------------------------
  chips      |	1.0.0	 |	chips		  | 1.更改函数类型，部分虚函数使用纯虚函数，部分虚函数转为普通函数，整理函数排列，拆分部分代码到子类，修改函数风格以统一;
----------------------------------------------------------------------------
*********************************************************************/

#pragma once

#define STANDALONE_COLLECTOR 1  
#define USE_LOCAL_TRUST_LIST 1 //关闭pipe通信

//#define MaxWaitSendQueueSize 500000

#include "event_record_manager.h"
#include <evntrace.h>
#include "etw_configuration.h"
#include "concurrent_queue.h"
#include "concurrentqueue.h"
#include "phf_detector.h"
#include "init_collector_factory.h"

typedef VOID (WINAPI *consume_event_func_ptr) (PEVENT_RECORD);
using EventRecordQueue = moodycamel::ConcurrentQueue<EventRecord*>;

class Output;
class InitCollector
{
	friend class InitCollectorFactory;

public:
	InitCollector(EM_InitCollectorMode mode);
	virtual ~InitCollector();

	static uint_64 m_nParseEventCount;
	static bool m_bCacheCleanFlag;
	static InitCollector* GetCollector() { return m_pInstance; }

	virtual void Init() = 0;
	virtual void Excute() = 0;
	virtual void Clean();

	EM_InitCollectorMode GetMode() const { return m_nMode; }
	LocalDetectorMode GetDetectorMode() const { return m_nDetectorMode; }
	void StopETWSession() { m_etwConfiguration.StopEtwSession(); }
	void OutputEventRecord(EventRecord* rec);

	void PushSendRecord(EventRecord* rec);
	EventRecord* PopSendRecord();
	size_t WaitSendDataSize();

	void SetProcessLastEvent(DWORD pid, uint_32 provider_id, uint_32 opcode);
	void GetProcessLastEvent(DWORD pid, uint_32& provider_id, uint_32& opcode);

protected:
	virtual void InitFilter() = 0;

	void InitEventStruct();
	void InitCallStackEnableEvent();
	void InitOutput();
	void InitDefaultValue();
	void InitVerification();

	void InitKeyAndMouseHook();
	virtual void InitThreadTask();
	virtual void GetSystemContext(); //when collector start,we need to get file/registry/.... object exist in system 
	void ParseAPISignatureFile(std::string file_name);

	EM_InitCollectorMode m_nMode;
	LocalDetectorMode m_nDetectorMode;
	ETWConfiguration m_etwConfiguration;

	/*moodycamel::ConcurrentQueue<EventRecord*>*/
	EventRecordQueue m_queWaitSendData;
	using OutputList = std::list<Output*>;

	/*std::list<Output*>*/
	OutputList m_listOutput;
	std::unordered_map<DWORD, uint_64> m_umapPid2LastEvent;

	// not ussed
	//void InitDLLModuleTree();
	//std::set<std::string> signature_dll_file_path_;
private:

    void UpdateUuidEventRecord(EventRecord* rec);                               // 事件添加UUID参数
    bool GetUuidbyProcessId(DWORD process_id, std::wstring& strUuid);           // 获取UUID参数
	bool GetHashidbyImage(DWORD process_id, std::wstring image, std::wstring& strHashid);  //当获取不到UUID时，获取HashID
    void insert_process_id_uuid_map(DWORD process_id, std::wstring strUUID);    // 进程创建时插入
    void erase_process_id_uuid_map(DWORD process_id);                           // 进程退出是删除
    bool query_process_id_uuid_map(DWORD process_id, std::wstring& strUuid);    // 查询

    std::unordered_map<DWORD, std::wstring> m_umapPid2Uuid;                  // 进程ID&UUID缓存map
	static InitCollector* m_pInstance;
	mutable RwLock m_lockSwapData;
	bool m_bSwapFlag = false;
	DEFINE_PROPERTY_READONLY(bool, insert_child_process);
	DEFINE_PROPERTY_READONLY(bool, sig_verification);
};

