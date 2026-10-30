#include "DllUnit.h"
#include <algorithm>
extern const int mapsize = 6;

DllUnit::umapptr DllUnit::ptr(new umap());
std::mutex DllUnit::mu;

std::vector<std::string> dllmap{ "advapi32.dll", "crypt32.dll" , "cryptsp.dll" , "rpcrt4.dll"  ,"wininet.dll" ,"ws2_32.dll" };

void DllUnit::increase(DWORD pid, std::string& dll)
{
	int index = -1;
	std::transform(dll.begin(), dll.end(), dll.begin(), ::tolower);
	for (int i = 0; i < dllmap.size(); ++i)
	{
		if (strstr(dll.c_str(), dllmap[i].c_str()))
			index = i;
	}
	if (index == -1) return;
	std::lock_guard<std::mutex> lk(mu);
	if (!ptr.unique())
	{
		//umapptr data_(new umap(*ptr));
		// with read event, will write into new empty map
		umapptr data_(new umap());
		ptr.swap(data_);
	}
	if (ptr.unique()) {
		auto t = ptr->find(pid);
		if (t == ptr->end()) (*ptr)[pid] = std::vector<int>(mapsize, 0);
		(*ptr)[pid][index]++;
	}
}

DllUnit::umapptr DllUnit::get()
{
	std::lock_guard<std::mutex> lk(mu);
	return ptr;
}


void DllUnit::get(DWORD pid, std::vector<int>& ans)
{
	auto data = get();
	auto iter = data->find(pid);
	if (iter != data->end()) {
		ans = iter->second;
	}
}

void DllUnit::clear()
{
	std::lock_guard<std::mutex> lk(mu);
	if (!ptr.unique())
	{
		umapptr data_(new umap());
		ptr.swap(data_);
	}
	if (ptr.unique()) {
		ptr->clear();
	}
}
