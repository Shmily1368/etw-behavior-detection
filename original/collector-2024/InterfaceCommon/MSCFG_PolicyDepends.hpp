#pragma once
#include "../ThirdPart/cJSON/include/cJsonHelper.hpp"
#include "MSCFG_PRCommon.hpp"
#include <map>

class CMSBasicInfo_NGEPConfigNode_Terminate
{
public:
    friend class CMSBasicInfo_NGEPPolicy;
    CMSBasicInfo_NGEPConfigNode_Terminate()
    {}
    ~CMSBasicInfo_NGEPConfigNode_Terminate() {}

    int nGetEnable() { return m_nEnable; }
    int nGetTerminate() { return m_nTerminate; }
    int nGetLocking() { return m_nLocking; }
    int nGetLockTime() { return m_nLockTime; }

    BOOL ReadSubNode_Terminate(cJSON* pJson, char* szTitle)
    {
        return ReadSubNode_TerminateEx(pJson, szTitle, MSBI_NP_TE_F_ALL);
    }

    enum MSBasicInfo_NGEPPolicy_TerminateEx_Flag
    {
        MSBI_NP_TE_F_ENABLE = 1,
        MSBI_NP_TE_F_TERMINATE = 2,
        MSBI_NP_TE_F_LOCKING = 4,
        MSBI_NP_TE_F_LOCKING_TIME = 8,
        MSBI_NP_TE_F_ALL = MSBI_NP_TE_F_ENABLE | MSBI_NP_TE_F_TERMINATE | MSBI_NP_TE_F_LOCKING | MSBI_NP_TE_F_LOCKING_TIME,
    };
    BOOL ReadSubNode_TerminateEx(cJSON* pJson, char* szTitle, int nFlag)
    {
        cJSON* titleType = cJSON_GetObjectItem(pJson, szTitle);
        if (titleType == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadSubNode_Terminate %s failed", szTitle);
            return FALSE;
        }
        return ReadNode_TerminateEx(titleType, nFlag);
    }

    BOOL ReadNode_TerminateEx(cJSON* pJson, int nFlag)
    {
        if (pJson == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadNode_TerminateEx pJson is null");
            return FALSE;
        }
        if ((nFlag & MSBI_NP_TE_F_ENABLE) != 0)
            cJsonHelper::GetItemInt(pJson, "enable", m_nEnable);
        if ((nFlag & MSBI_NP_TE_F_TERMINATE) != 0)
            cJsonHelper::GetItemInt(pJson, "terminate", m_nTerminate);
        if ((nFlag & MSBI_NP_TE_F_LOCKING) != 0)
            cJsonHelper::GetItemInt(pJson, "locking", m_nLocking);
        if ((nFlag & MSBI_NP_TE_F_LOCKING_TIME) != 0)
            cJsonHelper::GetItemInt(pJson, "locking_time", m_nLockTime);
        return true;
    }

private:
    int m_nEnable = 0; // 开关
    int m_nTerminate = 0; // 阻断
    int m_nLocking = 0; // 锁定
    int m_nLockTime = 0; // 时长
};

class CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems
    : public CMSBasicInfo_NGEPConfigNode_Terminate
    , public CMSCFG_NGEPConfigNode_Items<std::string>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems()
    {}
    ~CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems() {}
private:
};

template<typename ItemType>
class CMSBasicInfo_NGEPConfigNode_TerminateAndItems
    : public CMSBasicInfo_NGEPConfigNode_Terminate
    , public CMSCFG_NGEPConfigNode_Items<ItemType>
{
    friend class CMSBasicInfo_NGEPPolicy;
    friend class CMSBasicInfo_NGEPRule;
    friend class CMSBasicInfo_NGEPRule_Common;
public:
    CMSBasicInfo_NGEPConfigNode_TerminateAndItems() {}
    ~CMSBasicInfo_NGEPConfigNode_TerminateAndItems() {}
private:
};

class CMSBasicInfo_NGEPPolicy_Common
{
    friend CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicy_Common() {}
    ~CMSBasicInfo_NGEPPolicy_Common() {}

    std::string GetPolicyTime() { return strPolicyTime; }
    std::string GetPolicyId() { return strPolicyId; }
    std::string GetPolicyName() { return strPolicyName; }

private:
    //utf_8
    std::string strPolicyTime;
    std::string strPolicyId;
    std::string strPolicyName;
};

class CMSBasicInfo_NGEPPolicyNode_LogCollector
    : private CMSCFG_NGEPConfigNode_Items<std::string>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_LogCollector() {}
    ~CMSBasicInfo_NGEPPolicyNode_LogCollector() {}
    std::string GetPath() { return m_strPath; }

    BOOL ReadNode_LogCollector(cJSON* pJson, char* szPathKey, char* szExtensionKey)
    {
        if (pJson == NULL)
            return FALSE;
        // 文件
        cJSON* jsonItemsFilePath = cJSON_GetObjectItem(pJson, szPathKey);
        if (jsonItemsFilePath == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Illegal Target failed jsonItemsFilePath failed");
            return FALSE;
        }
        m_strPath = jsonItemsFilePath->valuestring;
        // 后缀
        return ReadSubNode_Items(pJson, szExtensionKey);
    }
private:
    std::string m_strPath;
};

class CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode
{
    friend class CMSBasicInfo_NGEPPolicy;

public:
    CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode()
    {}

    CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode(
        _In_ CONST std::wstring& wstrGateway,
        _In_ CONST std::wstring& wstrMac
    )
    {
        m_wstrGateway = wstrGateway;
        m_wstrMac = wstrMac;
    }

    ~CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode()
    {}

    std::wstring
        GetGateway()
    {
        return m_wstrGateway;
    }

    std::wstring
        GetMac()
    {
        return m_wstrMac;
    }

private:
    std::wstring m_wstrGateway;
    std::wstring m_wstrMac;
};

class CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtect
    : public CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;

public:
    CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtect()
    {}

    ~CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtect()
    {}

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode>
        GetGatewayList()
    {
        return m_GatewayList;
    }

private:
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode> m_GatewayList;
};

class CMSBasicInfo_NGEPConfigNode_BeginAndEndTime
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_BeginAndEndTime() {}
    CMSBasicInfo_NGEPConfigNode_BeginAndEndTime(std::string& strBeginTime, std::string& strEndTime)
        : m_strBeginTime(strBeginTime)
        , m_strEndTime(strEndTime)
    {}
    ~CMSBasicInfo_NGEPConfigNode_BeginAndEndTime() {}

    std::string GetBeginTime() { return m_strBeginTime; }
    std::string GetEndTime() { return m_strEndTime; }
private:
    std::string m_strBeginTime;
    std::string m_strEndTime;
};

class CMSBasicInfo_NGEPConfigNode_Location
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_Location() {}
    CMSBasicInfo_NGEPConfigNode_Location(std::string& strProvince, std::string& strCity)
        : m_strProvince(strProvince)
        , m_strCity(strCity)
    {
        m_strProvinceW = CPykMgrTemplate<CP_UTF8>(m_strProvince.c_str());
        m_strCityW = CPykMgrTemplate<CP_UTF8>(m_strCity.c_str());
    }
    ~CMSBasicInfo_NGEPConfigNode_Location() {}

    std::string GetProvince() { return m_strProvince; }
    std::string GetCity() { return m_strCity; }
    std::wstring GetProvinceW() { return m_strProvinceW; }
    std::wstring GetCityW() { return m_strCityW; }

private:
    std::string m_strProvince;
    std::string m_strCity;

    std::wstring m_strProvinceW;
    std::wstring m_strCityW;
};

class CMSBasicInfo_NGEPPolicyNode_Regedit
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_Regedit() :m_nStatus(0) {}
    ~CMSBasicInfo_NGEPPolicyNode_Regedit() {}

    std::string GetRegName() { return m_strRegName; }
    std::string GetRegPath() { return m_strRegPath; }
    std::string GetRegValue() { return m_strRegValue; }
    int GetStatus() { return m_nStatus; }
private:
    std::string m_strRegName;
    std::string m_strRegPath;
    std::string m_strRegValue;
    int m_nStatus;
};

class CMSBasicInfo_NGEPConfigNode_Str2IntMap
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_Str2IntMap()
    {}
    ~CMSBasicInfo_NGEPConfigNode_Str2IntMap()
    {}
    void SetEvent(std::string& strEvent)
    {
        m_map[strEvent] = 1;
    }
    int GetEvent(std::string& strEvent)
    {
        return m_map[strEvent];
    }
    std::map<std::string, int> GetMap() { return m_map; }
private:
    std::map<std::string, int> m_map;
};

class CMSBasicInfo_NGEPPolicyNode_FileSafe
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_FileSafe() : m_nStatus(0)
        , m_nID(0)
    {}
    ~CMSBasicInfo_NGEPPolicyNode_FileSafe() {}

    std::string GetPath() { return m_strPath; }
    std::vector<std::string> GetFileName() { return m_niFileName.m_vctData; }
    std::vector<std::string> GetProcessName() { return m_niProcessName.m_vctData; }
    std::map<std::string, int> GetOperation() { return m_eventOperation.GetMap(); }
    int GetStatus() { return m_nStatus; }
    int GetID() { return m_nID; }
private:
    //文件路径
    std::string m_strPath;
    //文件名
    CMSCFG_NGEPConfigNode_Items<std::string> m_niFileName;
    //授权进程
    CMSCFG_NGEPConfigNode_Items<std::string> m_niProcessName;
    //检测动作 map中设置为1标识进行检测，add-添加, modify-修改, delete-删除
    CMSBasicInfo_NGEPConfigNode_Str2IntMap m_eventOperation; // 根据策略传递的动作 重新转换下
    //是否阻断 1-阻断
    int m_nStatus;
    int m_nID;
};

class CMSBasicInfo_NGEPConfigNode_OtherDevice
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_OtherDevice()
        :m_nSerialport(0)
        , m_nParallelport(0)
        , m_nInfrared(0)
        , m_nH1394(0)
        , m_nBluetooth(0)
        , m_nCDROM(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_OtherDevice() {}

private:
    int m_nSerialport; // 串口
    int m_nParallelport; // 并口
    int m_nInfrared; // 红外
    int m_nH1394; // 1394
    int m_nBluetooth; // 蓝牙
    int m_nCDROM; // 光驱
};

class CMSBasicInfo_NGEPConfigNode_AccountCrack
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_AccountCrack()
        : m_nInterval(0)
        , m_nLimit(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_AccountCrack() {}
    int GetInterval() { return m_nInterval; }
    int GetLimit() { return m_nLimit; }
private:
    int m_nInterval;
    int m_nLimit;
};

class CMSBasicInfo_NGEPConfigNode_Backup
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_Backup() :m_nBackupEnable(0)
        , m_nNeglectMin(0)
        , m_nNeglectSize(0)
        , m_nBackupSize(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_Backup() {}

    int GetBackupEnable() { return m_nBackupEnable; }
    int GetNeglectMin() { return m_nNeglectMin; }
    int GetNeglectSize() { return m_nNeglectSize; }
    int GetBackupSize() { return m_nBackupSize; }
    BOOL ReadSubNode_Backup(cJSON* pJson)
    {
        cJSON* BackObject = cJSON_GetObjectItem(pJson, "backup");
        if (BackObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour encrypt backup failed");
            return FALSE;
        }
        else
        {
            cJsonHelper::GetItemInt(BackObject, "enable", m_nBackupEnable);
            cJsonHelper::GetItemInt(BackObject, "neglect_min", m_nNeglectMin);
            cJsonHelper::GetItemInt(BackObject, "neglect_size", m_nNeglectSize);
            cJsonHelper::GetItemInt(BackObject, "backup_size", m_nBackupSize);
        }
        return TRUE;
    }
private:
    int m_nBackupEnable;
    int m_nNeglectMin;
    int m_nNeglectSize;
    int m_nBackupSize;
};

class CMSBasicInfo_NGEPConfigNode_MinifilterData
    : public CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<std::string>
    , private CMSBasicInfo_NGEPConfigNode_Backup
{
    friend CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_MinifilterData() :m_nHide(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_MinifilterData() {}
    int GetHide() { return m_nHide; }
private:
    int m_nHide;
};

class CMSBasicInfo_NGEPConfigNode_NetworkIllegalConnect
    : private CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<std::string>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_NetworkIllegalConnect() :m_nInterval(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_NetworkIllegalConnect() {}

    int GetInterval() { return m_nInterval; }
private:
    int m_nInterval;
};

class CMSBasicInfo_NGEPConfigNode_NetworkPortScan
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_NetworkPortScan() :m_nRequestPeriod(0)
        , m_nRequestCount(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_NetworkPortScan() {}

    int GetRequestPeriod() { return m_nRequestPeriod; }
    int GetRequestCount() { return m_nRequestCount; }
private:
    int m_nRequestPeriod;
    int m_nRequestCount;
};

class CMSBasicInfo_NGEPConfigNode_NetworkSensitivePort
    : private CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<int>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_NetworkSensitivePort()
    {}
    ~CMSBasicInfo_NGEPConfigNode_NetworkSensitivePort() {}

private:
};

class CMSBasicInfo_NGEPConfigNode_AccountLocal
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_AccountLocal()
        : m_nTerminateMode(0)
        , m_nTimeEnable(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_AccountLocal() {}

    int GetTerminateMode() { return m_nTerminateMode; }
    int GetTimeEnable() { return m_nTimeEnable; }
private:
    //0-下次注销 1-立即注销
    int m_nTerminateMode;
    int m_nTimeEnable;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_BeginAndEndTime> m_npiTimelist;

};

class CMSBasicInfo_NGEPConfigNode_AccountRemote
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_AccountRemote()
        : m_nTerminateMode(0)
        , m_nTimeEnable(0)
        , m_nLocationEnable(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_AccountRemote() {}

    int GetTerminateMode() { return m_nTerminateMode; }
    int GetTimeEnable() { return m_nTimeEnable; }
    int GetLocationEnable() { return m_nLocationEnable; }
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_BeginAndEndTime> GetTimelist() { return m_npiTimelist; }
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_Location> GetLocationlist() { return m_npiLocationlist; }

private:
    //0-下次注销 1-立即注销
    int m_nTerminateMode;
    int m_nTimeEnable;
    int m_nLocationEnable;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_BeginAndEndTime> m_npiTimelist;
    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPConfigNode_Location> m_npiLocationlist;
};

class CMSBasicInfo_NGEPConfigNode_AccountUserChanges
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_AccountUserChanges()
        : m_nGroupEnable(0)
        , m_nUserEnable(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_AccountUserChanges() {}
    int GetGroupEnable() { return m_nGroupEnable; }
    int GetUserEnable() { return m_nUserEnable; }
private:
    int m_nGroupEnable;
    int m_nUserEnable;
};

class CMSBasicInfo_NGEPPolicyNode_SensitiveRegedit
    : private CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPPolicyNode_Regedit>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_SensitiveRegedit() {}
    ~CMSBasicInfo_NGEPPolicyNode_SensitiveRegedit() {}

private:

};

class CMSBasicInfo_NGEPPolicyNode_MiddlewarePeFile
    : private CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<std::string>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_MiddlewarePeFile() {}
    ~CMSBasicInfo_NGEPPolicyNode_MiddlewarePeFile() {}

    int GetExclude() { return m_nExclude; }
private:
    int m_nExclude;
};

class CMSBasicInfo_NGEPPolicyNode_MiddleFileIdentify
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_MiddleFileIdentify() {}
    ~CMSBasicInfo_NGEPPolicyNode_MiddleFileIdentify() {}

private:
    CMSCFG_NGEPConfigNode_Items<std::string> m_niTarget;
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_ScriptFile;
    CMSBasicInfo_NGEPPolicyNode_MiddlewarePeFile m_PEFile;
};

class CMSBasicInfo_NGEPPolicyNode_IllegalScriptIdentify
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_IllegalScriptIdentify() {}
    ~CMSBasicInfo_NGEPPolicyNode_IllegalScriptIdentify() {}
    int GetBackDoor() { return m_nBackDoor; }
    int GetUseKeyword() { return m_nUseKeyword; }

private:
    int m_nBackDoor;
    int m_nUseKeyword;

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPPolicyNode_LogCollector> m_niTargetData;
    CMSCFG_NGEPConfigNode_Items<std::string> m_niCustomKeyword;
    CMSCFG_NGEPConfigNode_Items<std::string> m_niDefaultkeyword;
};

class CMSBasicInfo_NGEPPolicyNode_WebshellFileIdentify
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPPolicyNode_WebshellFileIdentify() {}
    ~CMSBasicInfo_NGEPPolicyNode_WebshellFileIdentify() {}
    int GetBackDoor() { return m_nBackDoor; }
    int GetUseDefaultRule() { return m_nUseDefaultRule; }
    int GetDetectMode() { return m_nDetectMode; }
    int GetDetectEngine() { return m_nDetectEngine; }

private:
    int m_nBackDoor;
    int m_nUseDefaultRule; // 是否使用系统规则库
    int m_nDetectMode; // 1宽松模式 2严格模式
    int m_nDetectEngine; // 1 正则检测 2 统计检测 3 哈希检测 4 机器学习检测 预留以后使用

    CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPPolicyNode_LogCollector> m_niTargetData;
};

class CMSBasicInfo_NGEPConfigNode_LogcollectorFile
    : public CMSBasicInfo_NGEPConfigNode_Terminate
    , private CMSCFG_NGEPConfigNode_Items<CMSBasicInfo_NGEPPolicyNode_LogCollector>
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_LogcollectorFile() {}
    ~CMSBasicInfo_NGEPConfigNode_LogcollectorFile() {}

private:

};

class CMSBasicInfo_NGEPConfigNode_NetFlow
    : private CMSBasicInfo_NGEPConfigNode_Terminate
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_NetFlow()
        :m_nInterval(0)
        , m_nDownFlow(0)
        , m_nUpFlow(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_NetFlow() {}

private:
    int m_nInterval;
    int m_nDownFlow;
    int m_nUpFlow;
};

class CMSBasicInfo_NGEPConfigNode_Virus
{
    friend class CMSBasicInfo_NGEPPolicy;
public:
    CMSBasicInfo_NGEPConfigNode_Virus()
        :m_nNeglectSize(0)
        , m_nReservedSpace(0)
        , m_nAutomate(0)
        , m_nWhiteNum(0)
        , m_nRealTimeCheckEnable(0)
        , m_nScanningKillEnable(0)
        , m_nScanEnable(0)
        , m_nScanWay(0)
        , m_nScanCronDay(0)
    {}
    ~CMSBasicInfo_NGEPConfigNode_Virus() {}

private:
    int m_nNeglectSize; // 忽略文件大小(MB)
    int m_nReservedSpace; // 保留空间访问大小(GB)
    int m_nAutomate; // 处理方式, 0: 询问我, 1: 自动处理
    int m_nWhiteNum;
    int m_nRealTimeCheckEnable; // 实时检测
    int m_nScanningKillEnable; // 病毒查杀
    CMSCFG_NGEPConfigNode_Items<std::string> m_pFileList; // 白名单

    int m_nScanEnable;
    int m_nScanWay; // 扫描方式 1: 全盘扫描, 2: 快速扫描
    std::string m_strScanCronType; // 扫描周期 day: 每天扫描, week: 每周扫描, month: 每月扫描
    int m_nScanCronDay; // 按天值0, 按周月为日期值
    std::string m_StrScanCronTime; // 时间
};