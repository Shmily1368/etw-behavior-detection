#include "CallstackUnit.h"
#include <algorithm>
#include <assert.h>

extern const int g_nRansomapi_maxsize;

std::unordered_map<DWORD, std::shared_ptr<std::vector<int>>> CallstackUnit::m_spumpPid2Index;
std::mutex CallstackUnit::m_mutex;

void CallstackUnit::increase(DWORD pid, int index)
{
	assert(index >= 0 && index < g_nRansomapi_maxsize);
	if (index == -1)
		return;
	std::lock_guard<std::mutex> lk(m_mutex);
	if (!m_spumpPid2Index.count(pid))
		m_spumpPid2Index[pid] = std::make_shared<std::vector<int>>(g_nRansomapi_maxsize, 0);
	(*m_spumpPid2Index[pid])[index]++;
}

std::shared_ptr<std::vector<int>> CallstackUnit::GetAndClear(DWORD pid)
{
	std::shared_ptr<std::vector<int>> pTemp = std::make_shared<std::vector<int>>(g_nRansomapi_maxsize, 0);
	std::lock_guard<std::mutex> lk(m_mutex);
	if (m_spumpPid2Index.count(pid))
		pTemp.swap(m_spumpPid2Index[pid]);
	return pTemp;
}