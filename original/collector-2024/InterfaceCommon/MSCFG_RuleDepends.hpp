#pragma once
#include "Log4cplusBase.h"
#include "../ThirdPart/cJSON/include/cJsonHelper.hpp"
#include "MSCFG_PRCommon.hpp"
#include <map>
class CMSBasicInfo_NGEPConfigNode_Reader
{
public:
    CMSBasicInfo_NGEPConfigNode_Reader() {}
    ~CMSBasicInfo_NGEPConfigNode_Reader() {}

    virtual BOOL ReadNode(cJSON* pJson) = 0;
private:

};

class CMSBasicInfo_NGEPRule_Events
{
    //friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_Events()
    {}
    ~CMSBasicInfo_NGEPRule_Events()
    {}
    void SetEvent(std::string& strEvent)
    {
        m_mapReuleEvents[strEvent] = 1;
    }
    int GetEvent(std::string& strEvent)
    {
        return m_mapReuleEvents[strEvent];
    }
    BOOL ReadNode_Events(cJSON* pJson)
    {
        cJSON* eventObject = cJSON_GetObjectItem(pJson, "event_names");
        if (eventObject != NULL)
        {
            int nEventNum = cJSON_GetArraySize(eventObject);
            for (int k = 0; k < nEventNum; k++)
            {
                cJSON* eventNameObject = cJSON_GetArrayItem(eventObject, k);
                if (eventNameObject != NULL)
                {
                    std::string strT(eventNameObject->valuestring);
                    SetEvent(strT);
                }
            }
        }
        else
            WriteLog4cPlusBaseA(WARN_LEVEL, "event_names is null");
        return TRUE;
    }
private:
    std::map<std::string, int> m_mapReuleEvents;
};

class CMSBasicInfo_NGEPRule_Common :public CMSBasicInfo_NGEPRule_Events
    , private CMSCFG_NGEPConfigNode_Items<std::string>

{
    friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_Common() {}
    ~CMSBasicInfo_NGEPRule_Common() {}

private:
};

class CMSBasicInfo_NGEPRule_File :public CMSBasicInfo_NGEPRule_Events
{
    friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_File() {}
    ~CMSBasicInfo_NGEPRule_File() {}
    std::string GetFileName() { return m_strFileName; }
    std::string GetFilePath() { return m_strFilePath; }
    std::string GetFileExt() { return m_strFileExt; }
    std::string GetFileMD5() { return m_strFileMD5; }
    std::string GetProcessName() { return m_strProcessName; }
    std::string GetProcessPath() { return m_strProcessPath; }

    BOOL ReadNode_File(cJSON* pJson)
    {
        cJsonHelper::GetJsonString(pJson, "filename", m_strFileName);
        cJsonHelper::GetJsonString(pJson, "filepath", m_strFilePath);
        cJsonHelper::GetJsonString(pJson, "extension", m_strFileExt);
        cJsonHelper::GetJsonString(pJson, "md5", m_strFileMD5);
        cJsonHelper::GetJsonString(pJson, "process_path", m_strProcessPath);
        cJsonHelper::GetJsonString(pJson, "process_name", m_strProcessName);
        return TRUE;
    }
private:
    std::string m_strFileName;
    std::string m_strFilePath;
    std::string m_strFileExt;
    std::string m_strFileMD5;
    std::string m_strProcessName;
    std::string m_strProcessPath;
};

class CMSBasicInfo_NGEPRule_Process :public CMSBasicInfo_NGEPRule_Events
    , public CMSBasicInfo_NGEPConfigNode_Reader
{
    friend class CMSBasicInfo_NGEPRule;
public:
    typedef enum _MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE
    {
        MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_EQUAL = 0,
        MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_CONTAIN = 1,
        MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE_NOT_CONTAIN = 2,
    } MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE, * PMS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE;

    CMSBasicInfo_NGEPRule_Process() {}
    ~CMSBasicInfo_NGEPRule_Process() {}
    std::wstring GetProcessName() { return m_wstrProcessName; }
    std::wstring GetProcessPath() { return m_wstrProcessPath; }
    std::wstring GetProcessCommandLine() { return m_wstrProcessCommandLine; }
    MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE GetParam() { return m_enumParam; }
    std::wstring GetMD5() { return m_wstrMD5; }
    std::wstring GetProcessUser() { return m_wstrProcessUser; }
    std::wstring GetParentProcessName() { return m_wstrParentProcessName; }
    std::wstring GetRemoteIP() { return m_wstrRemoteIP; }

    BOOL ReadNode_Process(cJSON* pJson)
    {
        std::string strTemp;

        cJsonHelper::GetJsonString(pJson, "process_name", strTemp);
        m_wstrProcessName = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "process_path", strTemp);
        m_wstrProcessPath = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "process_commandline", strTemp);
        m_wstrProcessCommandLine = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "param", strTemp);
        m_enumParam = (MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE)atoi(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "md5", strTemp);
        m_wstrMD5 = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "process_user", strTemp);
        m_wstrProcessUser = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "parent_process_name", strTemp);
        m_wstrParentProcessName = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        cJsonHelper::GetJsonString(pJson, "remote_ip", strTemp);
        m_wstrRemoteIP = CPykMgrTemplate<CP_ACP>(strTemp.c_str());

        return TRUE;
    }

    virtual BOOL ReadNode(cJSON* pJson)
    {
        BOOL bRet = FALSE;
        do
        {
            if (!ReadNode_Process(pJson))
                break;
            if (!ReadNode_Events(pJson))
                break;
            bRet = TRUE;
        } while (false);
        return bRet;
    }
private:
    std::wstring m_wstrProcessName;
    std::wstring m_wstrProcessPath;
    std::wstring m_wstrProcessCommandLine;
    MS_ENUM_PROCESS_FILTER_COMMAND_LINE_TYPE m_enumParam;
    std::wstring m_wstrMD5;
    std::wstring m_wstrProcessUser;
    std::wstring m_wstrParentProcessName;
    std::wstring m_wstrRemoteIP;
};

class CMSBasicInfo_NGEPRule_PortControl
{
    friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_PortControl() {}
    ~CMSBasicInfo_NGEPRule_PortControl() {}

    std::string GetIP() { return m_strIP; }
    std::string GetProtocol() { return m_strProtocol; }
    std::string GetPort() { return m_strPort; }
    std::string GetDirection() { return m_strDirection; }
private:
    std::string m_strIP;
    std::string m_strProtocol;
    std::string m_strPort;
    std::string m_strDirection;
};

class CMSBasicInfo_NGEPRule_Sign
{
    friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_Sign() {}
    ~CMSBasicInfo_NGEPRule_Sign() {}

    std::string GetCompany() { return m_strCompany; }
    std::string GetFingerprint() { return m_strFingerprint; }
private:
    std::string m_strCompany;
    std::string m_strFingerprint;
};

class CMSBasicInfo_NGEPRule_Risk : private CMSCFG_NGEPConfigNode_Items<std::string>

{
    friend class CMSBasicInfo_NGEPRule;
public:
    CMSBasicInfo_NGEPRule_Risk() :m_nId(0) {}
    ~CMSBasicInfo_NGEPRule_Risk() {}
    int GetId() { return m_nId; }
private:
    int m_nId;
};