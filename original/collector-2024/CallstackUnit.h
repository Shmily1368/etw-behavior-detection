#pragma once
#include <memory>
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>


class CallstackUnit
{
public:
	static void increase(DWORD pid, int index);
	static std::shared_ptr<std::vector<int>> GetAndClear(DWORD pid);

private:
	static std::unordered_map<DWORD, std::shared_ptr<std::vector<int>>> m_spumpPid2Index;
	static std::mutex m_mutex;
};