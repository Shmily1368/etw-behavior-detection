#pragma once
#include "MSCFG_Rule.hpp"
#include "MSEnum.h"
//#include "MD5/FileMd5Helper.hpp"
class CMSBasicInfo_NGEPRuleMatcher
{
public:
    CMSBasicInfo_NGEPRuleMatcher()
    {}
    ~CMSBasicInfo_NGEPRuleMatcher()
    {}

    static BOOL CheckFilterFile(CMSBasicInfo_NGEPRule* pRule
        , std::wstring& strFilePath
        , std::wstring& strProcessName
        , std::wstring& strProcessPath
        , std::string& strFileMd5)
    {
        auto niRule = pRule->m_niRuleFilterFile;
        BOOL blRet = FALSE;
        if (strFilePath.empty() || niRule.GetItemNum() == 0)
            return FALSE;

        std::wstring strFileName = PathFindFileName(strFilePath.c_str());
        auto itor = niRule.m_vctData.begin();
        for (itor; itor != niRule.m_vctData.end(); itor++)
        {
            if (itor->GetFileName().empty()
                && itor->GetFileMD5().empty())
                continue;
            std::wstring strFilterFileName = CPykMgrTemplate<CP_UTF8>(itor->GetFileName().c_str());
            std::wstring strFilterFilePath;
            std::wstring strFilterProcessName;
            std::wstring strFilterProcessPath;

            if (!PathMatchSpec(strFileName.c_str(), strFilterFileName.c_str()))
                continue;

            if (!itor->GetFilePath().empty())
            {
                strFilterFilePath = CPykMgrTemplate<CP_UTF8>(itor->GetFilePath().c_str());
                if (!PathMatchSpec(strFilePath.c_str(), strFilterFilePath.c_str()))
                    continue;
            }

            if (!itor->GetProcessName().empty())
            {
                strFilterProcessName = CPykMgrTemplate<CP_UTF8>(itor->GetProcessName().c_str());
                if (strFilterProcessName != strProcessName)
                    continue;
            }

            if (!itor->GetProcessPath().empty())
            {
                strFilterProcessPath = CPykMgrTemplate<CP_UTF8>(itor->GetProcessPath().c_str());
                if (strFilterProcessPath != strProcessPath)
                    continue;
            }

            if (!itor->GetFileMD5().empty())
            {
                //if (strFileMd5.empty())
                //    GetFileMd5(strFilePath, strFileMd5, FALSE);

                if (strFileMd5.empty())
                    continue;

                if (itor->GetFileMD5() == strFileMd5)
                {
                    blRet = TRUE;
                    break;
                }
                else
                    continue;
            }

            blRet = TRUE;
            break;
        }
        return blRet;
    }

    static BOOL CheckFilterFile(CMSBasicInfo_NGEPRule* pRule
        , LPCTSTR szFilePath
        , LPCTSTR szProcessName
        , LPCTSTR szProcessPath
        , LPCSTR szFileMd5)
    {
        std::string strFileMd5(szFileMd5);
        std::wstring strFilePath(szFilePath);
        std::wstring strProcessName(szProcessName);
        std::wstring strProcessPath(szProcessPath);
        return CheckFilterFile(pRule
            , strFilePath
            , strProcessName
            , strProcessPath
            , strFileMd5);
    }

	static BOOL
		CheckProcess(
			_In_ CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process>& pmProcess
			, std::wstring& strProcessName
			, std::wstring& strProcessPath
			, std::wstring& strCommandLine
			, std::wstring& strMd5
			, std::wstring& strProcessUser
			, std::wstring& strParentProcessName
		)
	{
		BOOL bRet = FALSE;


		do
		{
			for (std::vector<CMSBasicInfo_NGEPRule_Process>::iterator it = pmProcess.m_vctData.begin(); it != pmProcess.m_vctData.end(); it++)
			{
				if (it->GetProcessName().length())
				{
					if (PathMatchSpec(strProcessName.c_str(), it->GetProcessName().c_str()))
					{
						bRet = TRUE;
					}
					else
					{
						bRet = FALSE;
						continue;
					}
				}

				if (it->GetProcessPath().length())
				{
					if (PathMatchSpec(strProcessPath.c_str(), it->GetProcessPath().c_str()))
					{
						bRet = TRUE;
					}
					else
					{
						bRet = FALSE;
						continue;
					}
				}

				if (it->GetProcessCommandLine().length())
				{
					switch (it->GetParam())
					{
					case MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_EQUAL:
					{
						//进程过滤名单匹配，由于命令行结尾带空格，策略中自动去掉，特殊处理一下
						wstring wstrCommandLineTemp = strCommandLine;
						wstrCommandLineTemp = wstrCommandLineTemp.erase(wstrCommandLineTemp.find_last_not_of(L" ") + 1);
						if (0 == _wcsicmp(wstrCommandLineTemp.c_str(), it->GetProcessCommandLine().c_str()))
						{
							bRet = TRUE;
						}
						else
						{
							bRet = FALSE;
							continue;
						}

						break;
					}
					case MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_CONTAIN:
					{
						if (NULL != StrStrI(strCommandLine.c_str(), it->GetProcessCommandLine().c_str()))
						{
							bRet = TRUE;
						}
						else
						{
							bRet = FALSE;
							continue;
						}

						break;
					}
					case MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_NOT_CONTAIN:
					{
						if (NULL == StrStrI(strCommandLine.c_str(), it->GetProcessCommandLine().c_str()))
						{
							bRet = TRUE;
						}
						else
						{
							bRet = FALSE;
							continue;
						}

						break;
					}
					default:
					{
						bRet = FALSE;
						continue;

						break;
					}
					}
				}

				if (it->GetMD5().length())
				{
					if (0 == _wcsicmp(strMd5.c_str(), it->GetMD5().c_str()))
					{
						bRet = TRUE;
					}
					else
					{
						bRet = FALSE;
						continue;
					}
				}

				if (it->GetProcessUser().length())
				{
					if (0 == _wcsicmp(strProcessUser.c_str(), it->GetProcessUser().c_str()))
					{
						bRet = TRUE;
					}
					else
					{
						bRet = FALSE;
						continue;
					}
				}

				if (it->GetParentProcessName().length())
				{
					if (PathMatchSpec(strParentProcessName.c_str(), it->GetParentProcessName().c_str()))
					{
						bRet = TRUE;
					}
					else
					{
						bRet = FALSE;
						continue;
					}
				}

				if (bRet)
				{
					break;
				}
			}
		} while (FALSE);

		return bRet;
	};



#ifdef MS_STRUCT_PROCESS_FILTER_INFO
    BOOL
        CheckProcessFilter(
            _In_ CONST MS_STRUCT_PROCESS_FILTER_INFO& structProcessFilterFullInfo,
            _In_ CONST BOOL bCheckLocalFilter
        );

    VOID
        ConvertProcessInfoToProcessFilterInfo(
            _In_ CONST PROCESSINFO& structProcessInfo,
            _Inout_ MS_STRUCT_PROCESS_FILTER_INFO& structProcessFilterFullInfo
        );

    VOID
        ConvertFileInfoToProcessFilterInfo(
            _In_ CONST MAGIC_MINI_FILE_NOTIFI& structFileInfo,
            _Inout_ MS_STRUCT_PROCESS_FILTER_INFO& structProcessFilterFullInfo
        );

    VOID
        ConvertRegistryInfoToProcessFilterInfo(
            _In_ CONST REGISTRYINFO& structRegistryInfo,
            _Inout_ MS_STRUCT_PROCESS_FILTER_INFO& structProcessFilterFullInfo
        );

    VOID
        ConvertNetInfoToProcessFilterInfo(
            _In_ CONST NET_TUPLE& structNetInfo,
            _Inout_ MS_STRUCT_PROCESS_FILTER_INFO& structProcessFilterFullInfo
        );
#endif // MS_STRUCT_PROCESS_FILTER_INFO    


private:
};