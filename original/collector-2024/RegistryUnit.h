#pragma once
#include <memory>
#include <Windows.h>
#include <unordered_map>
#include <mutex>

enum class registryops:int
{
	createops = 0,
	deleteops = 1,
	queryops  = 2,
	setops    = 3
};

class RegistryUnit 
{
public:
	/*std::unordered_map<DWORD, int>*/
	using umap = std::unordered_map<DWORD, int>;
	/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
	using umapptr = std::shared_ptr<umap>;
	static void increase(DWORD pid, registryops ops);
	static int GetAndClear(DWORD pid, registryops ops);

private:
	/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
	static umapptr ptr_create;
	static std::mutex cmu;
	/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
	static umapptr ptr_delete;
	static std::mutex dmu;
	/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
	static umapptr ptr_query;
	static std::mutex qmu;
	/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
	static umapptr ptr_set;
	static std::mutex smu;
};

/*
todo
\Microsoft\Cryptography\
HKCR\Applications
HKCR\TypeLib
HKCU\Software\Microsoft\RestartManager

*/