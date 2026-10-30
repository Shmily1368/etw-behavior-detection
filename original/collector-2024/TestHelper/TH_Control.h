#pragma once
//以下宏均控制一些测试代码或是临时解决方案处理逻辑

// ETW模块统计测试
// 弃用
//#define ETW_FILTER_TEST

// ETW InitCollectorOnlineParse的etw回调中系统EVENT_RECORD记录到csv文件开关
//#define ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST

// ETW Units记录到csv文件开关
//#define ETW_UNIT_RECORD_TEST

// ETW event记录到csv文件开关
//#define ETW_EVENT_RECORD_TEST

// ETW feature记录到csv文件开关
//#define ETW_FEATURE_RECORD_TEST

//#define ETW_HASH_TEST

// ETW延时统计追踪状态
//#define ETW_DELAY_EXIT_AND_RECORD_TRACE_INFO

#define ETW_USE_ENTROPY