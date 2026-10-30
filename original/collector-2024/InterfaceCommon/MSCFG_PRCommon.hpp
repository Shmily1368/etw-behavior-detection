#pragma once
#include <Windows.h>
#include <vector>

template<typename ItemType>
class CMSCFG_NGEPConfigNode_Items_Base_
{
    friend class CMSBasicInfo_NGEPPolicy;
    friend class CMSBasicInfo_NGEPRule;
    friend class CMSBasicInfo_NGEPRule_Common;
public:
    CMSCFG_NGEPConfigNode_Items_Base_() :m_nItemNum(0)
    {}
    ~CMSCFG_NGEPConfigNode_Items_Base_() {}

    std::vector<ItemType> m_vctData;
    int GetItemNum() { return m_nItemNum; }
    void SetItemNum(int nIn) { m_nItemNum = nIn; }
    void Clear()
    {
        m_vctData.clear();
        m_nItemNum = 0;
    }

    BOOL ReadSubNode_Items(cJSON* pJson, char* szTitle)
    {
        cJSON* titleType = cJSON_GetObjectItem(pJson, szTitle);
        if (titleType == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadSubNode_Items %s failed", szTitle);
            return FALSE;
        }
        return ReadNode_Items(titleType);
    }

    virtual BOOL ReadNode_Items(cJSON* pJson) = 0;
private:
    int m_nItemNum;
};

template<typename ItemType>
class CMSCFG_NGEPConfigNode_Items: public CMSCFG_NGEPConfigNode_Items_Base_<ItemType>
{
    friend class CMSBasicInfo_NGEPPolicy;
    friend class CMSBasicInfo_NGEPRule;
    friend class CMSBasicInfo_NGEPRule_Common;
public:
    CMSCFG_NGEPConfigNode_Items() {}
    ~CMSCFG_NGEPConfigNode_Items() {}

    BOOL ReadNode_Items(cJSON* pJson) {
        pJson;
        return false; 
    }
};

template <>
class CMSCFG_NGEPConfigNode_Items<int> : public CMSCFG_NGEPConfigNode_Items_Base_<int>
{
public:
    BOOL ReadNode_Items(cJSON* pJson) {
        Clear();
        int nExtCount = cJSON_GetArraySize(pJson);
        SetItemNum(nExtCount);
        if (nExtCount != 0)
        {
            for (int j = 0; j < nExtCount; j++)
            {
                cJSON* jsonItem = cJSON_GetArrayItem(pJson, j);
                if (jsonItem == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour track pExt Array");
                    continue;
                }
                m_vctData.push_back(jsonItem->valueint);
            }
        }
        return true;
    }
};

template <>
class CMSCFG_NGEPConfigNode_Items <std::string> : public CMSCFG_NGEPConfigNode_Items_Base_<std::string>
{
public:
    BOOL ReadNode_Items(cJSON* pJson) {
        Clear();
        int nExtCount = cJSON_GetArraySize(pJson);
        SetItemNum(nExtCount);
        if (nExtCount != 0)
        {
            for (int j = 0; j < nExtCount; j++)
            {
                cJSON* jsonItem = cJSON_GetArrayItem(pJson, j);
                if (jsonItem == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour track pExt Array");
                    continue;
                }
                m_vctData.push_back(jsonItem->valuestring);
            }
        }
        return true;
    }
};