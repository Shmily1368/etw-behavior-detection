#pragma once
#include <Windows.h>
#include "MSReg.h"
#include <string>
/*
[HKEY_LOCAL_MACHINE\SYSTEM\InstallMagicInfo]
"InstallPath"="C:\\Program Files (x86)\\NGEP"
"ClientVersion"="5.0.9.0906"
"IP"="127.0.0.1"
"MAC"="40-B0-76-10-04-5C"
"IPV6"="fe80::c906:3de6:f235:6c63"
"SkuMode"="UUID"
"Skustring"="878808eb97a335494d3abe485444bc40"
"Backup"="C:\\MepDir\\Backup"
"IsoArea"="C:\\MepDir\\IsoArea"
"VirusArea"="C:\\MepDir\\VirusArea"
*/
#define NGEPREGMGR_REGPATH L"SYSTEM\\InstallMagicInfo"
class CNgepRegMgr
{
public:
	CNgepRegMgr()
	{}
	~CNgepRegMgr()
	{}

	bool LoadReg()
	{
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"InstallPath", m_strInstallPath);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"ClientVersion", m_strClientVersion);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"IP", m_strIP);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"MAC", m_strMAC);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"IPV6", m_strIPV6);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"SkuMode", m_strSkuMode);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"Skustring", m_strSkustring);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"Backup", m_strBackup);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"IsoArea", m_strIsoArea);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"VirusArea", m_strVirusArea);
		CMSReg::ReadReg(HKEY_LOCAL_MACHINE, NGEPREGMGR_REGPATH, L"DebugCfgDir", m_strDebugCfgDir);

		return true;
	}

	std::wstring m_strInstallPath;
	std::wstring m_strClientVersion;
	std::wstring m_strIP;
	std::wstring m_strMAC;
	std::wstring m_strIPV6;
	std::wstring m_strSkuMode;
	std::wstring m_strSkustring;
	std::wstring m_strBackup;
	std::wstring m_strIsoArea;
	std::wstring m_strVirusArea;
	std::wstring m_strDebugCfgDir;
};
