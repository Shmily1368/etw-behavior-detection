#pragma once
#include <memory>
#include <Windows.h>
#include <unordered_map>
#include <vector>
#include <mutex>
#include <string>

/*
defined in event_record_subclass.cpp

STRING_SET EventRecordImage::_dll_need_rva_ransom_set =
{
	"advapi32.dll",
	"Crypt32.dll",
	"cryptsp.dll",  
	"Rpcrt4.dll",
	"Wininet.dll",
	"Ws2_32.dll",
};
*/



class DllUnit
{
public:
	using umap = std::unordered_map<DWORD, std::vector<int>>;
	using umapptr = std::shared_ptr<umap>;
	static void increase(DWORD pid, std::string& dll);
	static umapptr get();
	static void get(DWORD pid, std::vector<int>& ans);
	static void clear();

private:
	static umapptr ptr;
	static std::mutex mu;
}; 