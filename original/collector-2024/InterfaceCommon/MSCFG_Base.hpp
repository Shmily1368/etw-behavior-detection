#pragma once
class MSCFG_ReloadHelper
{
public:
	MSCFG_ReloadHelper() {}
	~MSCFG_ReloadHelper() {}

	bool IsChanged(std::wstring & strCfgFilePath)
	{
		bool bRet = false;
		struct _stat64i32 attr = { 0 };
		_wstat(strCfgFilePath.c_str(), &attr);
		bRet = !(attr.st_mtime == m_tRecord);
		m_tRecord = attr.st_mtime;
		return bRet;
	}
private:
	time_t m_tRecord = 0;
};
