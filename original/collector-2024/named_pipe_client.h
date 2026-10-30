#pragma once

#include "process_info.h"
#include "json_include/rapidjson/document.h"
#include "concurrentqueue.h"

#include <thread>

//#define  PIPE_Name 

class NamedPipeClient
{
	SINGLETON_DEFINITION(NamedPipeClient);

public:
	NamedPipeClient();
	~NamedPipeClient();

	//create
	void InitPipe();
	//read
	bool ReadPipe(char** buf);
	//write
	void WritePipe(const ProcessInfoItem& item);
	void WritePipe(const rapidjson::Document& json);

	std::string TransClassToString(const ProcessInfoItem& item);

private:
	void _ConnectPipe();
	void _ClosePipe();
	void _PushData(const String& data);
	void _WriteDataToPipe();

private:
	Mutex m_lock;
	moodycamel::ConcurrentQueue<String> m_queueData;
    bool m_bSwapFlag = false;
	bool m_bStopFlag;
	std::thread m_threadWorker;

	HANDLE m_hNamedPipeWrite;
	HANDLE m_hNamedPipeRead;
	//std::string  send_content;
	std::wstring m_strPipeNameWrite;
	std::wstring m_strPipeNameRead;
};
