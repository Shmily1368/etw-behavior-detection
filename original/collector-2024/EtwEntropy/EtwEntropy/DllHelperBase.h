#pragma once
#include <xstring>
#include <Windows.h>
#include <vector>
#include <map>
#include <functional>
#include "../../InterfaceCommon/Log4cplusBase.h"

class CDllHelperBase
{
public:
	CDllHelperBase() {}
	~CDllHelperBase() {}

	bool LoadSdk(const wchar_t* lpDllName, const wchar_t* lpDllPath = nullptr)
	{
		HMODULE h = NULL;
		if (lpDllPath != nullptr && _waccess(lpDllPath, 0) == 0)
		{
			WriteLog4cPlusBaseW(WARN_LEVEL, L"lpDllPath is not null And is Existed:%s", lpDllPath);
			h = LoadLibrary(lpDllPath);
			if (h == NULL)
				WriteLog4cPlusBaseW(ERROR_LEVEL, L"LoadLibrary %s Failed %d", lpDllPath, GetLastError());
		}
		else
			WriteLog4cPlusBaseA(WARN_LEVEL, "lpDllPath is null or is not Existed CDllHelperBase");
		if (h == NULL)
			h = LoadLibrary(lpDllName);
		if (h)
		{
			auto itor = m_vctFunName.begin();
			for (itor; itor != m_vctFunName.end(); itor++)
				//for (auto i : m_vctFunName)
				m_mapFunName2FunPtr[(*itor).c_str()] = GetProcAddress(h, (*itor).c_str());
		}
		else
		{
			WriteLog4cPlusBaseA(ERROR_LEVEL, "LoadLibrary Failed %d", GetLastError());
			return false;
		}
		WriteLog4cPlusBaseW(INFO_LEVEL, L"LoadSdk end");
		return true;
	}

	FARPROC GetFunPtr(const char* szFunName)
	{
		return m_mapFunName2FunPtr[szFunName];
	}

	std::vector<std::string> m_vctFunName;
private:
	std::map<std::string, FARPROC> m_mapFunName2FunPtr;
};

template <typename T>
std::function<T> Farproc2Fun(FARPROC lpfnGetProcessID) {
	std::function<T> func(reinterpret_cast<T*>(lpfnGetProcessID));
	return func;
}
