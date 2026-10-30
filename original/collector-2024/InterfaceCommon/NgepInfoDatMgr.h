#pragma once
#include <Windows.h>
#include <xstring>
#include <Shlwapi.h>
// #include "Log4cplusBase.h"
//#include "MSOperationSystem.h"
//#include "MSResource.h"
#include <functional>
#include "MSCFG_Base.hpp"

#define OPERATION_MODE_NORAML 0 // 常规模式
#define OPERATION_MODE_OPERATE 1 // 运维模式
#define OPERATION_MODE_LEARNING 2 // 学习模式

class CNgepInfoDatMgr:public MSCFG_ReloadHelper
{
public:
    CNgepInfoDatMgr()
    {
        m_nBidirectionalAuthenticationState = 0;

        m_nResourceLimitCPURate = 0;
        m_nResourceLimitMemory = 0;
        m_nResourceLimitCheckNetKBPerSecond = 0;
        m_nOfflineLogSpace = 0;
        m_nIsolationSpace = 0;
    }
    CNgepInfoDatMgr(std::wstring& strNgepInfoDat) :m_strNgepInfoDatMgr(strNgepInfoDat)
    {
        assert(!m_strNgepInfoDatMgr.empty());

        m_nBidirectionalAuthenticationState = 0;

        m_nResourceLimitCPURate = 0;
        m_nResourceLimitMemory = 0;
        m_nResourceLimitCheckNetKBPerSecond = 0;
        m_nOfflineLogSpace = 0;
        m_nIsolationSpace = 0;
    }
    ~CNgepInfoDatMgr()
    {}

    bool LoadConfig()
    {
        assert(!m_strNgepInfoDatMgr.empty());
        //if (CMSOperationSystem::GetInstance()->IsProcessor64())
        // m_strNgepInfoDatMgr = CMSResource::GetInstance()->m_mapResourceList[MS_ENUM_RESOURCE_ID_CONFIG_INFO_DAT].wstrX64BinaryPathName;
        //else
        // m_strNgepInfoDatMgr = CMSResource::GetInstance()->m_mapResourceList[MS_ENUM_RESOURCE_ID_CONFIG_INFO_DAT].wstrX86BinaryPathName;
        if (PathFileExists(m_strNgepInfoDatMgr.c_str()))
        {
            if (!IsChanged(m_strNgepInfoDatMgr))
            {
                WriteLog4cPlusBaseW(DEBUG_LEVEL, L"%s is not changed", m_strNgepInfoDatMgr.c_str());
                return true;
            }
            m_dwPort = GetPrivateProfileInt(L"Server", L"Port", 0, m_strNgepInfoDatMgr.c_str());
            m_dwOperationMode = GetPrivateProfileInt(L"Server", L"OperationMode", 0, m_strNgepInfoDatMgr.c_str());
            m_dwLanguageCN = GetPrivateProfileInt(L"Server", L"LanguageCN", 0, m_strNgepInfoDatMgr.c_str());
            m_dwCenpir = GetPrivateProfileInt(L"Server", L"Cenpir", 0, m_strNgepInfoDatMgr.c_str());
            m_dwCenMou = GetPrivateProfileInt(L"Server", L"CenMou", 0, m_strNgepInfoDatMgr.c_str());
            m_dwUploadSample = GetPrivateProfileInt(L"Server", L"UploadSample", 0, m_strNgepInfoDatMgr.c_str());

            m_strHost = GetString(L"Server", L"Host");
            m_strProtocol = GetString(L"Server", L"Protocol");
            m_strVersion = GetString(L"Server", L"Version");
            m_strServerList = GetString(L"Server", L"ServerList");
            m_strCollectVer = GetString(L"Server", L"CollectVer");
            m_strVirusLibVer = GetString(L"Server", L"VirusLibVer");
            m_strVirusAppVer = GetString(L"Server", L"VirusAppVer");
            m_strWeakDicVer = GetString(L"Server", L"WeakDicVer");
            m_strIPWryVer = GetString(L"Server", L"IPWryVer");
            m_strBaseLineVer = GetString(L"Server", L"BaseLineVer");
            m_strWebShellVer = GetString(L"Server", L"WebShellVer");
            m_wstrTenantId = GetString(L"Server", L"tenant_id");

            m_dwEtwGearAdjustMent = GetInt(L"Etw", L"GearAdjustMent");
            m_dwEtwHardwareAdjustment = GetInt(L"Etw", L"HardwareAdjustment");
            m_dwEtwRansom = GetInt(L"Etw", L"Ransom");
            m_dwEtwTerminate = GetInt(L"Etw", L"Terminate");
            m_strEtwKafkaName = GetString(L"Etw", L"KafkaName");
            m_strEtwKafkaPwd = GetString(L"Etw", L"KafkaPwd");
            m_strEtwKafkaTopic = GetString(L"Etw", L"KafkaTopic");
            m_strEtwDetectorMode = GetString(L"Etw", L"DetectorMode");
            m_strEtwKafkaServer = GetString(L"Etw", L"KafkaServer");

            m_nBidirectionalAuthenticationState = GetInt(L"Server", L"BidirectionalAuthenticationState");

            m_nResourceLimitCPURate = GetInt(L"ClientConfig", L"ResourceLimitCPURate");
            m_nResourceLimitMemory = GetInt(L"ClientConfig", L"ResourceLimitMemory");
            m_nResourceLimitCheckNetKBPerSecond = GetInt(L"ClientConfig", L"ResourceLimitCheckNetKBPerSecond");
            m_nOfflineLogSpace = GetInt(L"ClientConfig", L"OfflineLogSpace");
            m_nIsolationSpace = GetInt(L"ClientConfig", L"IsolationSpace");
            m_wstrPortFilter = GetString(L"ClientConfig", L"PortFilter");
        }
        else
            return false;
        return true;
    }

    bool isLearningMode()
    {
        return (m_dwOperationMode == OPERATION_MODE_LEARNING) ? true : false;
    }


    bool WriteString2Config(LPCWSTR lpAppName
        , LPCWSTR lpKeyName
        , LPCWSTR lpString)
    {
        return WritePrivateProfileString(lpAppName
            , lpKeyName
            , lpString
            , m_strNgepInfoDatMgr.c_str());
    }

    std::wstring
        GetString(
            _In_ CONST std::wstring& wstrAppName,
            _In_ CONST std::wstring& wstrKeyName
        )
    {
        std::wstring wstrRet;

        WCHAR wchData[MAX_PATH * 8] = { 0 };


        do
        {
            if (0 == GetPrivateProfileString(
                wstrAppName.c_str(),
                wstrKeyName.c_str(),
                L"",
                wchData,
                _countof(wchData),
                m_strNgepInfoDatMgr.c_str()
            ))
            {
                break;
            }

            wstrRet = wchData;
        } while (FALSE);

        return wstrRet;
    }

    BOOL
        WriteInt(
            _In_ CONST std::wstring& wstrAppName,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST int nData
        )
    {
        BOOL bRet = FALSE;

        std::wstring wstrData;


        do
        {
            wstrData = std::to_wstring(nData);

            if (!WritePrivateProfileString(
                wstrAppName.c_str(),
                wstrKeyName.c_str(),
                L"",
                wstrData.c_str()
            ))
            {
                break;
            }

            bRet = TRUE;
        } while (FALSE);

        return bRet;
    }

    int
        GetInt(
            _In_ CONST std::wstring& wstrAppName,
            _In_ CONST std::wstring& wstrKeyName
        )
    {
        int nRet = 0;


        do
        {
            nRet = GetPrivateProfileInt(
                wstrAppName.c_str(),
                wstrKeyName.c_str(),
                0,
                m_strNgepInfoDatMgr.c_str()
            );
        } while (FALSE);

        return nRet;
    }

	bool isUploadSample()
	{
		return m_dwUploadSample;
	}

    DWORD m_dwPort = 0;
    DWORD m_dwOperationMode = 0;
    DWORD m_dwLanguageCN = 0;
    //授权字段 1-过期
    DWORD m_dwCenpir = 0;
    DWORD m_dwCenMou = 0;
    DWORD m_dwUploadSample = 0;
    std::wstring m_strHost;
    std::wstring m_strProtocol;
    std::wstring m_strVersion;
    std::wstring m_strServerList;
    std::wstring m_strCollectVer;
    std::wstring m_strVirusLibVer;
    std::wstring m_strVirusAppVer;
    std::wstring m_strWeakDicVer;
    std::wstring m_strIPWryVer;
    std::wstring m_strBaseLineVer;
    std::wstring m_strWebShellVer;
    std::wstring m_wstrTenantId;

    //def by KAFKAINFO
    std::wstring m_strEtwKafkaName;
    std::wstring m_strEtwKafkaPwd;
    std::wstring m_strEtwKafkaTopic;
    std::wstring m_strEtwDetectorMode;
    DWORD m_dwEtwGearAdjustMent = 0;
    DWORD m_dwEtwHardwareAdjustment = 0;
    DWORD m_dwEtwRansom = 0;
    DWORD m_dwEtwTerminate = 0;
    std::wstring m_strEtwKafkaServer;

    int m_nBidirectionalAuthenticationState;

    int m_nResourceLimitCPURate;
    int m_nResourceLimitMemory;
    int m_nResourceLimitCheckNetKBPerSecond;
    int m_nOfflineLogSpace;
    int m_nIsolationSpace;
    std::wstring m_wstrPortFilter;

private:
    /*
    Host=127.0.0.1
    Port=443
    Protocol=HTTPS
    Version=5.0.9.0906
    LanguageCN=1
    Cenpir=0
    CenMou=32512
    ServerList=127.0.0.1
    CollectVer=edr20210805
    VirusLibVer=5.0.8.0712
    VirusAppVer=1.0.0.22082501
    OperationMode=0
    WeakDicVer=20220915_100206
    IPWryVer=20210428
    BaseLineVer=20220412
    WebShellVer=20211223
    */


    std::wstring m_strNgepInfoDatMgr;
};
