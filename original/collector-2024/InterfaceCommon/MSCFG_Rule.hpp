#pragma once
#include "MSCFG_RuleDepends.hpp"

class CMSBasicInfo_NGEPRule
{
public:
    //CMSBasicInfo_NGEPRule()
    //{
    //    CMSBasicInfo_NGEPLocal::GetInstallPath(m_strRuleFilePath);
    //    if (m_strRuleFilePath.at(m_strRuleFilePath.length() - 1) != L'\\')
    //        m_strRuleFilePath += L"\\";
    //    m_strRuleFilePath += L"Narlf.lst";
    //}
    CMSBasicInfo_NGEPRule()
    {}
    CMSBasicInfo_NGEPRule(std::wstring& strRuleFilePath)
    {
        m_strRuleFilePath = strRuleFilePath;
    }
    ~CMSBasicInfo_NGEPRule() {}

    BOOL LoadRule()
    {
        BOOL bRet = FALSE;
        if (!PathFileExists(m_strRuleFilePath.c_str()))
        {
            WriteLog4cPlusBaseW(WARN_LEVEL, L"%s is not exsits", m_strRuleFilePath.c_str());
            return bRet;
        }

        HANDLE hFile = NULL;
        char* chData = nullptr;
        DWORD dwSize = 0;
        do
        {
            hFile = CreateFile(m_strRuleFilePath.c_str()
                , GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE
                , NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                WriteLog4cPlusBaseW(ERROR_LEVEL, L"CreateFile:%s, error:%d"
                    , m_strRuleFilePath.c_str(), GetLastError());
                break;
            }

            dwSize = GetFileSize(hFile, NULL);
            if (dwSize == 0)
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "size is zero error:%d", GetLastError());
                break;
            }

            chData = (char*)new char[dwSize + 1];
            if (chData == NULL)
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "new failed, error:%d", GetLastError());
                break;
            }
            memset(chData, 0, (dwSize + 1));
            DWORD dwReal = 0;
            if (!ReadFile(hFile, chData, dwSize, &dwReal, NULL))
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "readfile failed, error:%d", GetLastError());
                break;
            }
            bRet = TRUE;
        } while (false);

        if (hFile != NULL)
        {
            CloseHandle(hFile);
            hFile = NULL;
        }

        if (bRet)
        {
            // chData is utf8
            ReadRuleJson(chData);
        }

        if (chData != nullptr)
        {
            delete[] chData;
            chData = nullptr;
        }

        return bRet;
    }

private:
    std::wstring m_strRuleFilePath;
    BOOL ReadRuleJson(char* chData)
    {
        BOOL blRet = FALSE;
        cJSON* jsonObject = NULL;
        jsonObject = cJSON_Parse(chData);
        if (jsonObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "cJSON_Parse Root failed");
            return FALSE;
        }
        do
        {
            cJSON* codeObject = cJSON_GetObjectItem(jsonObject, "code");
            if (codeObject == NULL)
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "Read rule code != 0");
                break;
            }

            cJSON* dataObject = cJSON_GetObjectItem(jsonObject, "data");
            if (dataObject == NULL)
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "Read rule dataObject NULL");
                break;
            }

            // 可信名单
            if (!ReadRuleTrust(dataObject))
            {
                WriteLog4cPlusBaseA(WARN_LEVEL, "ReadRuleTrust failed");
                break;
            }
            // 黑名单
            if (!ReadRuleBlack(dataObject))
            {
                WriteLog4cPlusBaseA(WARN_LEVEL, "ReadRuleBlack failed");
                break;
            }
            // 可信证书
            if (!ReadRuleGlobal(dataObject))
            {
                WriteLog4cPlusBaseA(WARN_LEVEL, "ReadRuleGlobal failed");
                break;
            }
            // 白名单
            if (!ReadRuleWhite(dataObject))
            {
                WriteLog4cPlusBaseA(WARN_LEVEL, "ReadRuleWhite failed");
                break;
            }
            // 可信名单
            if (!ReadRuleFilter(dataObject))
            {
                WriteLog4cPlusBaseA(WARN_LEVEL, "ReadRuleFilter failed");
                break;
            }
            blRet = TRUE;
        } while (false);

        cJSON_Delete(jsonObject);
        return blRet;
    }

    BOOL ReadRuleTrust(cJSON* jsonObject)
    {
        cJSON* trustObject = cJSON_GetObjectItem(jsonObject, "trust");
        if (trustObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read trust code != 0");
            return FALSE;
        }
        ReadRuleProcess(trustObject, "process", m_niRuleTrustProcess);
        ReadRuleFile(trustObject, "file", m_niRuleTrustFile);
        ReadRuleCommon(trustObject, "ip", "ip_list", m_niRuleTrustIP);
        ReadRuleCommon(trustObject, "domain", "domain_list", m_niRuleTrustDomain);
        ReadRuleCommon(trustObject, "user", "user_list", m_niRuleTrustUsers);

        return TRUE;
    }
    BOOL ReadRuleBlack(cJSON* jsonObject)
    {
        cJSON* blackObject = cJSON_GetObjectItem(jsonObject, "black");
        if (blackObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read black code != 0");
            return FALSE;
        }
        ReadRuleProcess(blackObject, "process", m_niRuleBlackProcess);
        ReadRuleFile(blackObject, "file", m_niRuleBlackFile);
        ReadRuleCommon(blackObject, "ip", "ip_list", m_niRuleBlackIP);
        ReadRuleCommon(blackObject, "domain", "domain_list", m_niRuleBlackDomain);
        ReadRuleCommon(blackObject, "user", "user_list", m_niRuleBlackUsers);
        ReadRulePortControl(blackObject, "access_control", m_niRuleBlackPortControl);

        return TRUE;
    }
    BOOL ReadRuleGlobal(cJSON* jsonObject)
    {
        cJSON* gObject = cJSON_GetObjectItem(jsonObject, "global");
        if (gObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read global code != 0");
            return FALSE;
        }

        cJSON* gTrust = cJSON_GetObjectItem(gObject, "trust");
        if (gTrust == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read global trust == 0");
        }
        else
        {
            cJSON* globalSign = cJSON_GetObjectItem(gTrust, "sign");
            if (globalSign != NULL)
            {
                int nNum = cJSON_GetArraySize(globalSign);
                m_niRuleGlobalSign.m_nItemNum = nNum;
                if (nNum > 0)
                {
                    for (int k = 0; k < nNum; k++)
                    {
                        CMSBasicInfo_NGEPRule_Sign pTemp;
                        cJSON* pItem = cJSON_GetArrayItem(globalSign, k);
                        cJsonHelper::GetJsonString(pItem, "company", pTemp.m_strCompany);
                        cJsonHelper::GetJsonString(pItem, "fingerprint", pTemp.m_strFingerprint);
                    }
                }
            }
        }

        // 仓库 黑名单域名
        cJSON* gBlack = cJSON_GetObjectItem(gObject, "black");
        if (gBlack == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read global black == 0");
        }
        else
        {
            m_niRuleGlobalDomain.Clear();
            cJSON* globalDomain = cJSON_GetObjectItem(gBlack, "domain");
            if (globalDomain != NULL)
            {
                int nNum = cJSON_GetArraySize(globalDomain);
                m_niRuleGlobalDomain.m_nItemNum = nNum;
                if (nNum > 0)
                {
                    for (int i = 0; i < nNum; i++)
                    {
                        cJSON* ItemsDomain = cJSON_GetArrayItem(globalDomain, i);
                        if (ItemsDomain == NULL)
                        {
                            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read rule domain failed");
                            continue;
                        }
                        m_niRuleGlobalDomain.m_vctData.push_back(ItemsDomain->valuestring);
                    }
                }
            }
            m_niRuleGlobalMinner.Clear();
            cJSON* globalMinner = cJSON_GetObjectItem(gBlack, "minner");
            if (globalMinner != NULL)
            {
                int nNum = cJSON_GetArraySize(globalMinner);
                m_niRuleGlobalMinner.m_nItemNum = nNum;
                if (nNum > 0)
                {
                    for (int k = 0; k < nNum; k++)
                    {
                        cJSON* Items = cJSON_GetArrayItem(globalMinner, k);
                        if (Items == NULL)
                        {
                            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read rule minner failed");
                            continue;
                        }
                        m_niRuleGlobalMinner.m_vctData.push_back(Items->valuestring);
                    }
                }
            }
        }
        return TRUE;
    }
    BOOL ReadRuleWhite(cJSON* jsonObject)
    {

        cJSON* whiteObject = cJSON_GetObjectItem(jsonObject, "white");
        if (whiteObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read white code == 0");
            return FALSE;
        }

        ReadRuleCommon(whiteObject, "ip", "ip_list", m_niRuleWhiteIP);
        ReadRuleCommon(whiteObject, "domain", "domain_list", m_niRuleWhiteDomain);
        ReadRuleCommon(whiteObject, "user", "user_list", m_niRuleWhiteUsers);

        cJSON* riskObject = cJSON_GetObjectItem(whiteObject, "risk");
        if (riskObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read white risk code == 0");
            return FALSE;
        }

        //信息不全？app_type节点未读取使用
        m_niRuleWhiteWeakPWD.Clear();
        ReadRuleRisk(riskObject, "weak_passwd", "username", m_niRuleWhiteWeakPWD);
        m_niRuleWhiteRiskAccount.Clear();
        ReadRuleRisk(riskObject, "account", "username", m_niRuleWhiteRiskAccount);
        m_niRuleWhiteSystemRisk.Clear();
        ReadRuleRisk(riskObject, "sys", "rule_keys", m_niRuleWhiteSystemRisk);
        m_niRuleWhitePortControl.Clear();
        ReadRulePortControl(whiteObject, "access_control", m_niRuleWhitePortControl);

        return TRUE;
    }
    BOOL ReadRuleFilter(cJSON* jsonObject)
    {
        cJSON* FilterObject = cJSON_GetObjectItem(jsonObject, "filter");
        if (FilterObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Filter != 0");
            return FALSE;
        }
        ReadRuleProcess(FilterObject, "process", m_niRuleFilterProcess);
        ReadRuleFile(FilterObject, "file", m_niRuleFilterFile);
        ReadRuleCommon(FilterObject, "ip", "ip_list", m_niRuleFilterIP);
        ReadRuleCommon(FilterObject, "domain", "domain_list", m_niRuleFilterDomain);
        return TRUE;
    }

    BOOL ReadRuleProcess(const cJSON* jsonObject,const char* chFieldName
        , CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process>& pRuleProcess)
    {
        pRuleProcess.Clear();
        cJSON* processObject = cJSON_GetObjectItem(jsonObject, chFieldName);
        if (processObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetObjectItem %s null", chFieldName);
            return FALSE;
        }
        int nItemsNum = cJSON_GetArraySize(processObject);
        if (nItemsNum == 0)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArraySize %s is zero", chFieldName);
            return TRUE;
        }
        pRuleProcess.m_nItemNum = nItemsNum;
        for (int i = 0; i < nItemsNum; i++)
        {
            cJSON* Items = cJSON_GetArrayItem(processObject, i);
            if (Items != NULL)
            {
                CMSBasicInfo_NGEPRule_Process pTemp;
                pTemp.ReadNode_Process(Items);
                pTemp.ReadNode_Events(Items);
                pRuleProcess.m_vctData.push_back(pTemp);
            }
            else
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArrayItem is null");
        }
        return TRUE;
    }
    BOOL ReadRuleFile(const cJSON* jsonObject,const char* chFieldName
        , CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_File>& RuleFile)
    {
        RuleFile.Clear();
        cJSON* fileObject = cJSON_GetObjectItem(jsonObject, chFieldName);
        if (fileObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetObjectItem %s null", chFieldName);
            return FALSE;
        }
        int nItemsNum = cJSON_GetArraySize(fileObject);
        if (nItemsNum == 0)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArraySize %s is zero", chFieldName);
            return TRUE;
        }
        RuleFile.m_nItemNum = nItemsNum;
        for (int i = 0; i < nItemsNum; i++)
        {
            cJSON* Items = cJSON_GetArrayItem(fileObject, i);
            if (Items != NULL)
            {
                CMSBasicInfo_NGEPRule_File pTemp;
                pTemp.ReadNode_File(Items);
                pTemp.ReadNode_Events(Items);
                RuleFile.m_vctData.push_back(pTemp);
            }
        }

        return TRUE;
    }
    BOOL ReadRuleCommon(const cJSON* jsonObject,const char* chFieldName,const char* chListName
        , CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common>& pRuleCommon)
    {
        pRuleCommon.Clear();
        cJSON* fieldName = cJSON_GetObjectItem(jsonObject, chFieldName);
        if (fieldName == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetObjectItem %s null", chFieldName);
            return FALSE;
        }

        int nFieldNum = cJSON_GetArraySize(fieldName);
        if (nFieldNum == 0)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArraySize %s is zero", chFieldName);
            return TRUE;
        }
        pRuleCommon.m_nItemNum = nFieldNum;

        for (int i = 0; i < nFieldNum; i++)
        {
            cJSON* fieldObject = cJSON_GetArrayItem(fieldName, i);
            if (fieldObject == NULL)
            {
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read rule failed");
                continue;
            }
            cJSON* ListObject = cJSON_GetObjectItem(fieldObject, chListName);
            if (ListObject != NULL)
            {
                int nItemsNum = cJSON_GetArraySize(ListObject);
                if (nItemsNum == 0)
                    continue;
                CMSBasicInfo_NGEPRule_Common pTemp;
                pTemp.ReadNode_Items(ListObject);
                pTemp.ReadNode_Events(fieldObject);
                pRuleCommon.m_vctData.push_back(pTemp);
            }

        }

        return TRUE;
    }
    BOOL ReadRulePortControl(const cJSON* jsonObject,const char* chFieldName
        , CMSCFG_NGEPConfigNode_Items<CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_PortControl>>& pPortControl)
    {
        pPortControl.Clear();
        cJSON* fileObject = cJSON_GetObjectItem(jsonObject, chFieldName);
        if (fileObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetObjectItem %s null", chFieldName);
            return FALSE;
        }

        int nSecondNum = cJSON_GetArraySize(fileObject);
        pPortControl.m_nItemNum = nSecondNum;
        if (nSecondNum == 0)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArraySize %s is zero", chFieldName);
            return TRUE;
        }

        for (int i = 0; i < nSecondNum; i++)
        {
            CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_PortControl> pTemp;
            cJSON* Items = cJSON_GetArrayItem(fileObject, i);

            cJSON* ListObject = cJSON_GetObjectItem(Items, "connect_list");
            if (ListObject != NULL)
            {
                int nListItemsNum = cJSON_GetArraySize(ListObject);
                pTemp.m_nItemNum = nListItemsNum;
                if (nListItemsNum == 0)
                    continue;
                for (int k = 0; k < nListItemsNum; k++)
                {
                    CMSBasicInfo_NGEPRule_PortControl pTempTemp;
                    cJSON* ListItems = cJSON_GetArrayItem(ListObject, k);
                    if (ListItems != NULL)
                    {
                        cJsonHelper::GetJsonString(ListItems, "ip", pTempTemp.m_strIP);
                        cJsonHelper::GetJsonString(ListItems, "protocol", pTempTemp.m_strProtocol);
                        cJsonHelper::GetJsonString(ListItems, "port", pTempTemp.m_strPort);
                        cJsonHelper::GetJsonString(ListItems, "direction", pTempTemp.m_strDirection);
                    }
                    else
                        continue;
                    pTemp.m_vctData.push_back(pTempTemp);
                }
            }
            else
                continue;
            pPortControl.m_vctData.push_back(pTemp);
        }

        return TRUE;
    }
    BOOL ReadRuleRisk(const cJSON* jsonObject,const char* chFieldName,const char* chListName
        , CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Risk>& pRuleRisk)
    {
        pRuleRisk.Clear();
        cJSON* fieldName = cJSON_GetObjectItem(jsonObject, chFieldName);
        if (fieldName == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetObjectItem %s is null", chFieldName);
            return FALSE;
        }
        int nFieldNum = cJSON_GetArraySize(fieldName);
        if (nFieldNum == 0)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "cJSON_GetArraySize %s is zero", chFieldName);
            return TRUE;
        }
        pRuleRisk.m_nItemNum = nFieldNum;
        for (int i = 0; i < nFieldNum; i++)
        {
            cJSON* fieldObject = cJSON_GetArrayItem(fieldName, i);
            if (fieldObject == NULL)
            {
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read rule failed");
                continue;
            }

            cJSON* RuleObject = cJSON_GetObjectItem(fieldObject, "rule");
            if (RuleObject != NULL)
            {
                cJSON* ListObject = NULL;
                ListObject = cJSON_GetObjectItem(RuleObject, chListName);
                if (ListObject != NULL)
                {
                    CMSBasicInfo_NGEPRule_Risk pTemp;
                    pTemp.ReadNode_Items(ListObject);
                    cJSON* IDObject = cJSON_GetObjectItem(fieldObject, "id");
                    if (IDObject != NULL)
                        pTemp.m_nId = IDObject->valueint;
                    pRuleRisk.m_vctData.push_back(pTemp);
                }
            }
        }
        return TRUE;
    }
public:
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> m_niRuleTrustProcess;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_File> m_niRuleTrustFile;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleTrustIP;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleTrustDomain;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleTrustUsers;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> m_niRuleBlackProcess;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_File> m_niRuleBlackFile;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleBlackIP;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleBlackDomain;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleBlackUsers;
    CMSCFG_NGEPConfigNode_Items<CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_PortControl>> m_niRuleBlackPortControl;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Sign> m_niRuleGlobalSign;
    CMSCFG_NGEPConfigNode_Items<std::string> m_niRuleGlobalDomain;
    CMSCFG_NGEPConfigNode_Items<std::string> m_niRuleGlobalMinner;
    //CMSCFG_NGEPConfigNode_Items<std::string> m_niRuleGlobalSensitiveFile;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleWhiteIP;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleWhiteDomain;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleWhiteUsers;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Risk> m_niRuleWhiteWeakPWD;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Risk> m_niRuleWhiteRiskAccount;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Risk> m_niRuleWhiteSystemRisk;
    CMSCFG_NGEPConfigNode_Items<CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_PortControl>> m_niRuleWhitePortControl;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Process> m_niRuleFilterProcess;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_File> m_niRuleFilterFile;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleFilterIP;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPRule_Common> m_niRuleFilterDomain;
};