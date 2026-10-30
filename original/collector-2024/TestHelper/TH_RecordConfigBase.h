#pragma once
#include <Shlwapi.h>
#include "StringHelp.h"
#include <map>
class CTHRecordConfigBase
{
public:
	CTHRecordConfigBase(LPCTSTR lpRecordFileName = nullptr, LPCTSTR lpDefaultApp = nullptr)
	{
		TCHAR szPath[4096 + 1] = { 0 };
		GetModuleFileName(NULL, szPath, 4096);
		PathRemoveFileSpec(szPath);
		if (lpRecordFileName)
			PathAppend(szPath, lpRecordFileName);
		else
			PathAppend(szPath, L"THRecordConfigBase.ini");
		m_strConfigPath = szPath;
		OutputDebugStringW(m_strConfigPath.c_str());
		//m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>
		//	(L"THRecordConfigBase", FALSE));
		m_strDefaultApp = lpDefaultApp;
	}

	~CTHRecordConfigBase()
	{

	}

	BOOL PrepareConfig(LPCTSTR lpApp)
	{
		if (PathFileExists(m_strConfigPath.c_str()))
			DeleteFile(m_strConfigPath.c_str());
		auto i = m_mapCheckList.begin();
		for (; i != m_mapCheckList.end(); i++)
			WriteLocal(lpApp,i->first.c_str(), i->second);
		return TRUE;
	}

	BOOL PrepareConfig()
	{
		assert(!m_strDefaultApp.empty());
		return PrepareConfig(m_strDefaultApp.c_str());
	}

	void SetResult(LPCTSTR lpApp, LPCTSTR lpCheck, BOOL bResult)
	{
		if (m_mapCheckList.count(lpCheck) == 0)
		{
			m_mapCheckList.emplace(std::make_pair<std::wstring, BOOL>(lpCheck, bResult));
			WriteLocal(lpApp, lpCheck, bResult);
		}
		else
		{
			if (m_mapCheckList[lpCheck] == bResult)
				return;
			m_mapCheckList[lpCheck] = bResult;
			if (bResult)
				WriteLocal(lpApp, lpCheck, bResult);
		}
	}

	void SetResult(LPCTSTR lpCheck, BOOL bResult)
	{
		assert(!m_strDefaultApp.empty());
		return SetResult(m_strDefaultApp.c_str(), lpCheck, bResult);
	}

	void SetDefaultApp(LPCTSTR lpApp) 
	{
		m_strDefaultApp = lpApp; 
		assert(!m_strDefaultApp.empty());
	}
	std::map<std::wstring, BOOL> m_mapCheckList;

private:
	std::wstring m_strConfigPath;
	std::wstring m_strDefaultApp;
	inline BOOL WriteLocal(LPCTSTR lpApp, LPCTSTR lpKey, BOOL bResult)
	{
		BOOL bRet = WritePrivateProfileString(lpApp, lpKey, bResult ? L"TRUE" : L"FALSE", m_strConfigPath.c_str());
		if (!bRet)
			StringHelp::OutputDebugStringFormatW(L"PrepareConfig WritePrivateProfileString %s Failed %d"
				, m_strConfigPath.c_str(), GetLastError());
		return bRet;
	}

	inline BOOL WriteLocal(LPCTSTR lpKey, BOOL bResult)
	{
		assert(!m_strDefaultApp.empty());
		return WriteLocal(m_strDefaultApp.c_str(), lpKey, bResult);
	}
};