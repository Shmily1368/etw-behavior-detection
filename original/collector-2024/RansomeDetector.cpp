//#define _CRT_SECURE_NO_WARNINGS
#include "stdafx.h"
#include "RansomDetector.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
//#include "CJsonObject.hpp"
#include "unit.h"
#include "processTree.h"
#include "feature.h"
#include <stdio.h>
#include <stdlib.h>
#include <thread>
#include <mutex>
#include <condition_variable>

//#include <boost/chrono/duration.hpp>
//#include <boost/thread/thread.hpp>
//#pragma comment(lib, "ws2_32.lib")  

#define DEFAULT_BUFFER 500000 /*缓冲区大小*/
//std::mutex event_lock;//多线程标准输出同步锁
bool load_model(const std::string &model_file);
bool load_range(const string& restore_filename);

void unload_model();
void unload_range();

void processEvent(event& singleEvent);
extern unordered_map<int, std::shared_ptr<process>> g_umapProcessTree;
extern vector<std::shared_ptr<process>> g_vctProcessUnitTree;
extern unordered_map<string, vector<string>> g_umapFileMap;
extern const int testwindow = 5;

RansomDetector::RansomDetector()
{
	string range_path = "data\\features.all-etw.range";
	string model_path = "data\\features.all-etw.model";
	bool flag1 = load_model(model_path);
	bool flag2 = load_range(range_path);
	flag = flag1 && flag2;
}


RansomDetector::~RansomDetector()
{
	unload_range();
	unload_model();
}


void InitItemRepository(ItemRepository *ir)
{
	ir->write_position = 0; // 初始化产品写入位置.
	ir->read_position = 0; // 初始化产品读取位置.
}

void RansomDetector::Init(void)
{
	if (flag)
	{
		InitItemRepository(&m_ItemRepository);
		std::thread consumer(&RansomDetector::ConsumerTask, this); // 创建消费event,产生unit之线程.
		consumer.detach();
		std::thread thrTimeStamp([]() {
			while (1) {
				std::this_thread::sleep_for(std::chrono::seconds(testwindow));
				char szNow[MAX_PATH] = { 0 };
				SYSTEMTIME sysTime;
				GetLocalTime(&sysTime);
				StringHelp::StringFormatA(szNow, MAX_PATH, "%04d-%02d-%02d %02d:%02d:%02d"
					, sysTime.wYear, sysTime.wMonth, sysTime.wDay, sysTime.wHour, sysTime.wMinute, sysTime.wSecond);
				feature::InsertTimeStamp(szNow);
				}
			});
		thrTimeStamp.detach();
		
		int countes = 0;
		while (1) {
			std::this_thread::sleep_for(std::chrono::seconds(testwindow));
			{
				{
					std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
					cout << "live process num:" << g_umapProcessTree.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
				}

				std::unique_lock<std::mutex> lock_unit(unit_lock);
				feature::getUnits();                 //主线程定时将unit转为feature，并进行检测
				lock_unit.unlock();

				{
					std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
					cout << "process num:" << g_vctProcessUnitTree.size() << endl;
#endif // OUTPUT_COMMAND_LINE;
				}
				countes++;
				if (countes % 100 == 0)
				{
					countes = 0;
					WriteLog4cPlus(INFO_LEVEL, L"RansomDetector live process num: %d process num: %d fileMap num: %d", g_umapProcessTree.size(), g_vctProcessUnitTree.size(), g_umapFileMap.size());
#ifdef OUTPUT_COMMAND_LINE 
					int_64 sum_size = 0;
					for (auto i = g_umapFileMap.begin(); i != g_umapFileMap.end(); i++)
					{
						sum_size += (i->first.capacity() + 28);
						for (auto j = i->second.begin(); j != i->second.end(); j++)
							sum_size += ((*j).capacity() + 28);
					}
					sum_size = sum_size / 1024;
					string temp = "fileMap num sum_size memory: " + std::to_string(sum_size) + "KB";
					cout << temp.c_str() << endl;
					WriteLog4cPlusA(INFO_LEVEL, temp.c_str());
#endif // OUTPUT_COMMAND_LINE;
				}
			}
		}
	}
}

// add by zxw on 20191114
void ProduceItem(ItemRepository * ir, event item)
{
	// add 20191218 wate one microseconds；
	//boost::this_thread::sleep_for(boost::chrono::microseconds(1));
	std::unique_lock<std::mutex> lock(ir->event_mtx); // item buffer is full, just wait here.
	while (((ir->write_position + 1) % ITEMREPOSITORYSIZE) == ir->read_position) {
		(ir->repo_not_full).wait(lock);
	}

	/*if (item.EventName == "ProcessStart")
		std::cout << "position : ProduceItem " << " PID: " << item.arguments.ProcessId << " FileName: " << item.arguments.ImageFileName << std::endl;*/

	(ir->event_buffer)[ir->write_position] = item;

	(ir->write_position)++;                        // 写入位置后移.

	if (ir->write_position == ITEMREPOSITORYSIZE) // 写入位置若是在队列最后则重新设置为初始位置.
		ir->write_position = 0;

	(ir->repo_not_empty).notify_all();             // 通知消费者产品库不为空.
	lock.unlock();                                 // 解锁.
}
// add by zxw on 20191114
void RansomDetector::PushRansomRecord(event item) {

	/*if (item.EventName == "ProcessStart")
		std::cout << "position : PushRansomRecord " << " PID: " << item.arguments.ProcessId << " FileName: " << item.arguments.ImageFileName << std::endl;*/

	ProduceItem(&m_ItemRepository, item);

	_push_count++;
	if (_push_count % 100000 == 0) {
		std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
		cout << "producer: " << _push_count << endl;
#endif // OUTPUT_COMMAND_LINE;
		WriteLog4cPlus(INFO_LEVEL, L"PushRansomRecord producer:  %d", _push_count);
	}
}

void RansomDetector::ConsumeItem(ItemRepository *ir)
{
	event data;
	std::unique_lock<std::mutex> lock(ir->event_mtx);   // item buffer is empty, just wait here.
	while (ir->write_position == ir->read_position)
	{
		(ir->repo_not_empty).wait(lock);
	}

	data = (ir->event_buffer)[ir->read_position]; // 读取某一产品
	{
		std::unique_lock<std::mutex> lock_unit(unit_lock);

		/*if (data.EventName == "ProcessStart") 
			std::cout << "position : ConsumeItem " << " PID: " << data.arguments.ProcessId << " FileName: " << data.arguments.ImageFileName << std::endl;*/

		processEvent(data);
		lock_unit.unlock();                                 // 解锁.
	}

	(ir->read_position)++;                        // 读取位置后移

	if (ir->read_position >= ITEMREPOSITORYSIZE) // 读取位置若移到最后，则重新置位.
		ir->read_position = 0;

	(ir->repo_not_full).notify_all();             // 通知消费者产品库不为满.
	lock.unlock();                                // 解锁.
}


void RansomDetector::ConsumerTask()
{
	int j = 0;
	while (1)
	{
		// add 20191218 wate one microseconds；
		//boost::this_thread::sleep_for(boost::chrono::nanoseconds(100));
		ConsumeItem(&m_ItemRepository);
		j++;
		if (j % 100000 == 0) {
			std::lock_guard<std::mutex> lock(out_lock);
#ifdef OUTPUT_COMMAND_LINE       
			cout << "consumer: " << j << endl;
#endif // OUTPUT_COMMAND_LINE;
			WriteLog4cPlus(INFO_LEVEL, L"ConsumerTask consumer:  %d", j);
		}
	}
}


