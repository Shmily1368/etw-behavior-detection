#pragma once

// Writed by Zhenyuan(lizhenyuan@zju.edu.cn)
// Created 2018-5-2
// Updated 2018-5-29

#include <Windows.h>

#include <unordered_map>

#include "event_record.h"

class ExeModuleAddress {
public:
	ULONG64 image_base_;
	ULONG64 image_end_;
};

class CallstackPruning
{
public:
	CallstackPruning();
	~CallstackPruning();

	static bool pruning(EventRecord*);
	static bool pruningwithAPIName(EventRecord*);
	static bool pruningwithEntryAddress(EventRecord*);

	static std::unordered_map<ULONG64, ExeModuleAddress> m_umapProcessid2Exemoduleaddress;
	static std::unordered_map<DWORD, std::string> m_umapProcessid2LastApiName;
	static std::unordered_map<DWORD, ULONG64> m_umapProcessid2LastEntryAddress;
};

