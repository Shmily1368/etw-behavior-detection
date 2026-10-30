#include "RegistryUnit.h"

std::initializer_list<registryops> regoprations
{
	registryops::createops,
	registryops::deleteops,
	registryops::queryops,
	registryops::setops
};
/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
RegistryUnit::umapptr RegistryUnit::ptr_create(new umap());
std::mutex RegistryUnit::cmu;
/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
RegistryUnit::umapptr RegistryUnit::ptr_delete(new umap());
std::mutex RegistryUnit::dmu;
/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
RegistryUnit::umapptr RegistryUnit::ptr_query(new umap());
std::mutex RegistryUnit::qmu;
/*std::shared_ptr<std::unordered_map<DWORD, int>>*/
RegistryUnit::umapptr RegistryUnit::ptr_set(new umap());
std::mutex RegistryUnit::smu;

void RegistryUnit::increase(DWORD pid, registryops ops)
{ 
	auto pFun = [&](RegistryUnit::umapptr spUmap
		, std::mutex& mutexUmap)
	{
		std::lock_guard<std::mutex> lk(mutexUmap);
		if (!spUmap.unique())
		{
			umapptr data_(new umap());
			spUmap.swap(data_);
		}
		(*spUmap)[pid]++;
	};

	switch (ops)
	{
	case registryops::createops:
		pFun(ptr_create, cmu);
	break;
	case registryops::deleteops:
		pFun(ptr_delete, dmu);
	break;
	case registryops::queryops:
		pFun(ptr_query, qmu);
	break;
	case registryops::setops:
		pFun(ptr_set, smu);
	break;
	default:
		break;
	}
}

int RegistryUnit::GetAndClear(DWORD pid, registryops ops)
{
	int nRet = 0;
	auto pFun = [&](RegistryUnit::umapptr spUmap
		, std::mutex& mutexUmap)
	{
		int nRet = 0;
		std::lock_guard<std::mutex> lk(mutexUmap);
		auto iter = spUmap->find(pid);
		if (iter != spUmap->end())
		{
			nRet = (*iter).second;
			spUmap->erase(iter);
		}
		return nRet;
	};
	switch (ops)
	{
	case registryops::createops:
		nRet = pFun(ptr_create, cmu);
	break;
	case registryops::deleteops:
		nRet = pFun(ptr_delete, dmu);
	break;
	case registryops::queryops:
		nRet = pFun(ptr_query, qmu);
	break;
	case registryops::setops:
		nRet = pFun(ptr_set, smu);
	break;
	default:
		break;
	}
	return nRet;
}