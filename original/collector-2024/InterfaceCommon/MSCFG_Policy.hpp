#pragma once
#include "MSCFG_PolicyDepends.hpp"
#include "MSCFG_Base.hpp"

class CMSBasicInfo_NGEPPolicy:public MSCFG_ReloadHelper
{
public:
    //CMSBasicInfo_NGEPPolicy()
    //{
    //    CMSBasicInfo_NGEPLocal::GetInstallPath(m_strPolicyFilePath);
    //    if (m_strPolicyFilePath.at(m_strPolicyFilePath.length() - 1) != L'\\')
    //        m_strPolicyFilePath += L"\\";
    //    m_strPolicyFilePath += L"Nacvf.lst";
    //}
    CMSBasicInfo_NGEPPolicy() {}

    CMSBasicInfo_NGEPPolicy(std::wstring& strPolicyFilePath)
    {
        m_strPolicyFilePath = strPolicyFilePath;
    }

    ~CMSBasicInfo_NGEPPolicy() {}

    BOOL LoadPolicy()
    {
        BOOL bRet = FALSE;
        if (!PathFileExists(m_strPolicyFilePath.c_str()))
        {
            WriteLog4cPlusBaseW(ERROR_LEVEL, L"%s is not exsits", m_strPolicyFilePath.c_str());
            return bRet;
        }
        if (!IsChanged(m_strPolicyFilePath))
        {
            bRet = true;
            WriteLog4cPlusBaseW(DEBUG_LEVEL, L"%s is not changed", m_strPolicyFilePath.c_str());
            return bRet;
        }

        HANDLE hFile = NULL;
        char* chData = nullptr;
        DWORD dwSize = 0;
        do
        {
            hFile = CreateFile(m_strPolicyFilePath.c_str()
                , GENERIC_READ, FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE
                , NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
            if (hFile == INVALID_HANDLE_VALUE)
            {
                WriteLog4cPlusBaseW(ERROR_LEVEL, L"CreateFile:%s, error:%d"
                    , m_strPolicyFilePath.c_str(), GetLastError());
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
            DoXOR(0x10298, chData, dwSize);
            // chData is utf8
            ReadPolicyJson(chData);
        }

        if (chData != nullptr)
        {
            delete[] chData;
            chData = nullptr;
        }

        return bRet;
    }

private:
    std::wstring m_strPolicyFilePath;

    inline void DoXOR(DWORD dwKey, char* wzData, int nLen)
    {
        if (nLen)
        {
            while (nLen--)
                *(wzData++) ^= dwKey;
        }
    }

    BOOL ReadPolicyJson(char* chData)
    {
        BOOL bRet = FALSE;

        cJSON* jsonObject = NULL;
        jsonObject = cJSON_Parse(chData);
        if (jsonObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "cJSON_Parse failed");
            return bRet;
        }
        // 策略名称 ID 时间
        if (!ReadPolicyJsonCommon(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyJsonCommon failed");
        // 恶意行为防护 挖矿 防勒索
        if (!ReadPolicyBehaviour(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyBehaviour failed");
        // 进程 提权 mbr 隧道等
        if (!ReadPolicyProcess(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyProcess failed");
        // 网络
        if (!ReadPolicyNetwork(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyNetwork failed");
        // 帐号
        if (!ReadPolicyAccount(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyAccount failed");

        // 敏感
        if (!ReadPolicySensitive(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicySensitive failed");
        // 日志
        if (!ReadPolicyLogcollector(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyLogcollector failed");
        // 加固
        if (!ReadPolicyFasten(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyFasten failed");
        // 其他
        if (!ReadPolicyOther(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyOther failed");
        // 杀毒
        if (!ReadPolicyVirus(jsonObject))
            WriteLog4cPlusBaseA(ERROR_LEVEL, "ReadPolicyVirus failed");
        cJSON_Delete(jsonObject);

        return bRet;
    }
    BOOL ReadPolicyJsonCommon(cJSON* jsonObject)
    {
        cJsonHelper::GetJsonString(jsonObject, "policy_time", m_NGEPPolicy_Common.strPolicyTime);
        cJsonHelper::GetJsonString(jsonObject, "policy_id", m_NGEPPolicy_Common.strPolicyId);
        cJsonHelper::GetJsonString(jsonObject, "policy_name", m_NGEPPolicy_Common.strPolicyName);
        return TRUE;
    }
    BOOL ReadPolicyBehaviour(cJSON* jsonObject)
    {
        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "Read Behaviour protect failed");
            return FALSE;
        }

        cJSON* behaviourObject = cJSON_GetObjectItem(protectObject, "behaviour");
        if (behaviourObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "Read Behaviour behaviour failed");
            return FALSE;
        }

        // 挖矿
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour pool");
        m_ntBehaviourMining.ReadSubNode_Terminate(behaviourObject, "pool");
        cJSON* ransomwareObject = cJSON_GetObjectItem(behaviourObject, "ransomware");
        if (ransomwareObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour ransomware failed");
            return FALSE;
        }

        //EncaSwitchInfo(ransomwareObject,"track",m_ransomwareETW);
        ReadETWRansom(ransomwareObject);
        // minifilter 防勒索
        ReadMiniFilter(ransomwareObject);

        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour Leave");
        return TRUE;
    }
    BOOL ReadPolicyProcess(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Process Enter");

        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read process protect failed");
            return FALSE;
        }

        cJSON* processObject = cJSON_GetObjectItem(protectObject, "process");
        if (processObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect process failed");
            return FALSE;
        }

        m_ntProcessReverseShell.ReadSubNode_Terminate(processObject, "reverse_shell");
        m_ntProcessPrivilege.ReadSubNode_Terminate(processObject, "privilege");
        m_ntProcessMBR.ReadSubNode_Terminate(processObject, "mbr");
        m_ntProcessCommand.ReadSubNode_Terminate(processObject, "dangerous_command");
        m_ntProcessWebshell.ReadSubNode_Terminate(processObject, "webshell");
        m_ntProcessService.ReadSubNode_Terminate(processObject, "service_process");
        m_ntProcessFakeSys.ReadSubNode_Terminate(processObject, "fake_sys_process");
        m_ntProcessTunnel.ReadSubNode_Terminate(processObject, "tunnel");
        m_ntProcessRiskCommand.ReadSubNode_Terminate(processObject, "risk_command");
        m_ntProcessAbnormalProcess.ReadSubNode_Terminate(processObject, "abnormal_process");

        m_niProcessCommandTable.ReadSubNode_Items(processObject, "command_table_list");

        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Process Leave");
        return TRUE;
    }
    BOOL ReadPolicyNetwork(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Network Enter");

        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read network protect failed");
            return FALSE;
        }

        cJSON* networkObject = cJSON_GetObjectItem(protectObject, "network");
        if (networkObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect network failed");
            return FALSE;
        }

        m_ntNetworkDomain.ReadSubNode_Terminate(networkObject, "domain");

        ReadNetworkIllegalConnect(networkObject);
        ReadNetworkPortScan(networkObject);
        ReadNetworkSensitivePort(networkObject);
        ReadNetworkGatewayProtect(networkObject);

        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Network Leave");
        return TRUE;
    }
    BOOL ReadPolicyAccount(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Enter");

        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account protect failed");
            return FALSE;
        }

        cJSON* accountObject = cJSON_GetObjectItem(protectObject, "account");
        if (accountObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account network failed");
            return FALSE;
        }

        // Login
        cJSON* pLoginObject = cJSON_GetObjectItem(accountObject, "login");
        if (pLoginObject != NULL)
        {
            m_ntSystemAccountLogin.ReadNode_TerminateEx(pLoginObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);

            // 本地登录
            ReadAccountLocalLogin(pLoginObject);

            // 远程登录
            ReadAccountRemoteLogin(pLoginObject);

            // 暴力密码破解
            ReadAccountCrack(pLoginObject);
        }

        // 异常帐号
        m_SystemAccountAbnormal.ReadSubNode_TerminateEx(accountObject, "abnormal_user", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);

        // 用户变更监控
        cJSON* pUserChangesMonitorObject = cJSON_GetObjectItem(accountObject, "user_change");
        if (pUserChangesMonitorObject != NULL)
        {
            m_AccountUserChanges.ReadNode_TerminateEx(pUserChangesMonitorObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);

            cJSON* pLocalGroup = cJSON_GetObjectItem(pUserChangesMonitorObject, "user_group");
            if (pLocalGroup != NULL)
            {
                cJSON* pLocalGroupEnable = cJSON_GetObjectItem(pLocalGroup, "enable");
                if (pLocalGroupEnable != NULL)
                    m_AccountUserChanges.m_nGroupEnable = pLocalGroupEnable->valueint;
            }

            cJSON* pLocalUser = cJSON_GetObjectItem(pUserChangesMonitorObject, "user");
            if (pLocalUser != NULL)
            {
                cJSON* pLocalUserEnable = cJSON_GetObjectItem(pLocalUser, "enable");
                if (pLocalUserEnable != NULL)
                    m_AccountUserChanges.m_nUserEnable = pLocalUserEnable->valueint;
            }
        }
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Leave");
        return TRUE;
    }
    BOOL ReadPolicySensitive(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Sensitive Enter");

        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read network protect failed");
            return FALSE;
        }

        cJSON* sensitiveObject = cJSON_GetObjectItem(protectObject, "sensitive_info");
        if (sensitiveObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive failed");
            return FALSE;
        }

        //ReadSensitiveFile(sensitiveObject); 合并到
        m_SensitiveLogDelete.ReadSubNode_Terminate(sensitiveObject, "log_delete");
        //EncaSwitchInfo(sensitiveObject, "log_delete", m_SensitiveLogDelete); // log_delete 有个list， windows用不上就不解析了

        ReadSensitiveRegedit(sensitiveObject);
        ReadSensitiveFileSafe(sensitiveObject);
        ReadUSBFileMonitor(sensitiveObject);
        ReadMiddlewareVerify(sensitiveObject);
        ReadIllegalScriptVerify(sensitiveObject); // 非法脚本
        ReadWebshellVerify(sensitiveObject); // 非法脚本

        // 后门 非法脚本 webshell


        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Sensitive Leave");
        return TRUE;
    }
    BOOL ReadPolicyLogcollector(cJSON* jsonObject)
    {
        cJSON* protectObject = NULL;
        protectObject = cJSON_GetObjectItem(jsonObject, "protect");
        if (protectObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector failed");
            return FALSE;
        }

        cJSON* logObject = cJSON_GetObjectItem(protectObject, "logcollector");
        if (logObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector failed");
            return FALSE;
        }

        m_LogcollectorProcess.ReadSubNode_TerminateEx(logObject, "process", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_LogcollectorNework.ReadSubNode_TerminateEx(logObject, "network", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        cJSON* NetworkLogObject = cJSON_GetObjectItem(logObject, "network");
        if (NetworkLogObject != NULL)
            m_LogcollectorNework_dpi.ReadSubNode_TerminateEx(NetworkLogObject, "dpi", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_LogcollectorDNS.ReadSubNode_TerminateEx(logObject, "dnsquery", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_LogcollectorETW.ReadSubNode_TerminateEx(logObject, "etw", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_LogcollectorAuditPolicy.ReadSubNode_TerminateEx(logObject, "audit_policy", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);

        cJSON* fileObject = NULL;
        fileObject = cJSON_GetObjectItem(logObject, "file");
        if (fileObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file failed");
            return FALSE;
        }
        m_LogcollectorFile.ReadNode_TerminateEx(fileObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);

        if (m_LogcollectorFile.nGetEnable())
        {
            cJSON* fileObjectOpen = cJSON_GetObjectItem(fileObject, "open");
            if (fileObjectOpen == NULL)
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file open failed");
            else
            {
                m_LogcollectorFile_Open.ReadNode_TerminateEx(fileObjectOpen, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
                m_LogcollectorFile_Open.Clear();
                cJSON* fileObjectOpenList = cJSON_GetObjectItem(fileObjectOpen, "list");
                if (fileObjectOpenList == NULL)
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file open list failed");
                else
                {
                    int nFileListNum = cJSON_GetArraySize(fileObjectOpenList);
                    m_LogcollectorFile_Open.m_nItemNum = nFileListNum;
                    if (nFileListNum > 0)
                    {
                        for (int i = 0; i < nFileListNum; i++)
                        {
                            CMSBasicInfo_NGEPPolicyNode_LogCollector pTemp;
                            cJSON* jsonLogFileItems = cJSON_GetArrayItem(fileObjectOpenList, i);
                            if (jsonLogFileItems == NULL)
                                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file list array item failed");

                            else
                            {
                                pTemp.ReadNode_LogCollector(jsonLogFileItems, "filepath", "extension");
                                m_LogcollectorFile_Open.m_vctData.push_back(pTemp);
                            }
                        }
                    }
                }
            }
        }

        m_LogcollectorFile.Clear();
        cJSON* fileObjectList = cJSON_GetObjectItem(fileObject, "list");
        if (fileObjectList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file list failed");
            return FALSE;
        }

        int nFileListNum = cJSON_GetArraySize(fileObjectList);
        m_LogcollectorFile.m_nItemNum = nFileListNum;
        if (nFileListNum == 0)
            return FALSE;
        for (int i = 0; i < nFileListNum; i++)
        {
            CMSBasicInfo_NGEPPolicyNode_LogCollector pTemp;
            cJSON* jsonLogFileItems = cJSON_GetArrayItem(fileObjectList, i);
            if (jsonLogFileItems == NULL)
            {
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Log collector file list array item failed");
                return FALSE;
            }

            pTemp.ReadNode_LogCollector(jsonLogFileItems, "filepath", "extension");
            m_LogcollectorFile.m_vctData.push_back(pTemp);
        }


        return TRUE;
    }
    BOOL ReadPolicyFasten(cJSON* jsonObject)
    {
        cJSON* fastenObject = cJSON_GetObjectItem(jsonObject, "fasten");
        if (fastenObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read fasten failed");
            return FALSE;
        }

        // 资源 负载监控
        cJSON* resourceObject = cJSON_GetObjectItem(fastenObject, "resource");
        if (resourceObject != NULL)
        {
            m_ResourceMonitor.m_nEnable = resourceObject->valueint;
            ReadSystemResource(resourceObject);
            ReadProcessResource(resourceObject);
        }

        // 设备
        cJSON* deviceObject = cJSON_GetObjectItem(fastenObject, "device");
        if (deviceObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read device failed");
            return FALSE;
        }

        ReadNewPolicyUSBPrinterCDRom(deviceObject, "usb", m_FastenUSB);
        ReadNewPolicyUSBPrinterCDRom(deviceObject, "printer", m_FastenPrinter);
        ReadNewPolicyUSBPrinterCDRom(deviceObject, "cdrom", m_FastenCDRom);
        ReadNewExcludeUUID(deviceObject);

        ReadNewPolicyDeviceOther(deviceObject, "other", m_DeviceOther);
        return TRUE;
    }
    BOOL ReadPolicyOther(cJSON* jsonObject)
    {
        cJSON* otherObject = cJSON_GetObjectItem(jsonObject, "other");
        if (otherObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read other failed");
            return FALSE;
        }
        m_OtherUninstall.ReadSubNode_TerminateEx(otherObject, "allow_uninstall", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_OtherShowTray.ReadSubNode_TerminateEx(otherObject, "allow_ui_tray", CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        return TRUE;
    }
    BOOL ReadPolicyVirus(cJSON* jsonObject)
    {
        cJSON* virusObject = cJSON_GetObjectItem(jsonObject, "antivirus");
        if (virusObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read virus failed");
            return FALSE;
        }

        cJSON* virusAutomate = cJSON_GetObjectItem(virusObject, "automate");
        if (virusAutomate != NULL)
            m_VirusMonitor.m_nAutomate = virusAutomate->valueint;

        cJSON* virusNeglectSize = cJSON_GetObjectItem(virusObject, "neglect_size");
        if (virusNeglectSize != NULL)
            m_VirusMonitor.m_nNeglectSize = virusNeglectSize->valueint;

        cJSON* virusRealObject = cJSON_GetObjectItem(virusObject, "real_time_check");
        if (virusRealObject != NULL)
        {
            cJSON* virusRealEnable = cJSON_GetObjectItem(virusRealObject, "enable");
            if (virusRealEnable != NULL)
                m_VirusMonitor.m_nRealTimeCheckEnable = virusRealEnable->valueint;
        }

        // 实时扫描
        cJSON* virusReservedspace = cJSON_GetObjectItem(virusObject, "reserved_space");
        if (virusReservedspace != NULL)
            m_VirusMonitor.m_nReservedSpace = virusReservedspace->valueint;

        // 病毒查杀
        cJSON* virusScanningKill = cJSON_GetObjectItem(virusObject, "scanning_kill");
        if (virusScanningKill != NULL)
        {
            cJSON* ScanningKillEnable = cJSON_GetObjectItem(virusScanningKill, "enable");
            if (ScanningKillEnable != NULL)
                m_VirusMonitor.m_nScanningKillEnable = ScanningKillEnable->valueint;

            // 定时扫描
            cJSON* jsonCron = cJSON_GetObjectItem(virusScanningKill, "cron");
            if (jsonCron != NULL)
            {
                cJSON* jsonCronEnable = cJSON_GetObjectItem(jsonCron, "enable");
                if (jsonCronEnable != NULL)
                    m_VirusMonitor.m_nScanEnable = jsonCronEnable->valueint;

                // 扫描类型
                cJSON* jsonCronScanWay = cJSON_GetObjectItem(jsonCron, "scanning_way");
                if (jsonCronScanWay != NULL)
                    m_VirusMonitor.m_nScanWay = jsonCronScanWay->valueint;

                cJsonHelper::GetJsonString(jsonCron, "time_type", m_VirusMonitor.m_strScanCronType);
                cJsonHelper::GetItemInt(jsonCron, "day", m_VirusMonitor.m_nScanCronDay);
                cJsonHelper::GetJsonString(jsonCron, "time", m_VirusMonitor.m_StrScanCronTime);
            }
        }

        //信任区
        cJSON* jsonTrustList = cJSON_GetObjectItem(virusObject, "trust_list");
        if (jsonTrustList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "jsonTrustList NULL");
            return FALSE;
        }
        m_VirusMonitor.m_pFileList.ReadNode_Items(jsonTrustList);
        return TRUE;
    }

    BOOL ReadETWRansom(cJSON* jsonObject)
    {
        cJSON* trackObject = cJSON_GetObjectItem(jsonObject, "track");
        if (trackObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour trackObject failed");
            return FALSE;
        }

        m_netwBehaviourRansomwareETWDATA.ReadNode_TerminateEx(trackObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        m_netwBehaviourRansomwareETWDATA.ReadSubNode_Items(trackObject, "extension");
        return TRUE;
    }
    // 文件过滤驱动
    BOOL ReadMiniFilter(cJSON* jsonObject)
    {
        cJSON* encryptObject = cJSON_GetObjectItem(jsonObject, "encrypt");
        if (encryptObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "Read Behaviour encrypt failed");
            return FALSE;
        }

        m_nminiBehaviourRansomwareMinifilter.ReadNode_TerminateEx(encryptObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);

        cJSON* encryptObjectHide = cJSON_GetObjectItem(encryptObject, "hide");
        if (encryptObjectHide == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Behaviour encrypt hide failed");
            return FALSE;
        }
        m_nminiBehaviourRansomwareMinifilter.m_nHide = encryptObjectHide->valueint;
        m_nminiBehaviourRansomwareMinifilter.ReadSubNode_Items(encryptObject, "extension");
        m_nminiBehaviourRansomwareMinifilter.ReadSubNode_Backup(encryptObject);

        return TRUE;
    }

    BOOL ReadNetworkIllegalConnect(cJSON* jsonObject)
    {
        cJSON* connectObject = cJSON_GetObjectItem(jsonObject, "illegal_connect");
        if (connectObject == NULL)
        {
            WriteLog4cPlusBaseA(ERROR_LEVEL, "Read protect network illegal connect failed");
            return FALSE;
        }

        m_nicNetworkIllegalConnect.ReadNode_TerminateEx(connectObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        m_nicNetworkIllegalConnect.ReadSubNode_Items(connectObject, "address");

        cJSON* connectObjectInterval = cJSON_GetObjectItem(connectObject, "interval");
        if (connectObjectInterval != NULL)
            m_nicNetworkIllegalConnect.m_nInterval = connectObjectInterval->valueint;
        return TRUE;
    }
    BOOL ReadNetworkPortScan(cJSON* jsonObject)
    {
        cJSON* portObject = cJSON_GetObjectItem(jsonObject, "port");
        if (portObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect network port failed");
            return FALSE;
        }

        m_NetworkPortScan.ReadNode_TerminateEx(portObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_LOCKING_TIME);

        cJSON* portObjectRequestPeriod = cJSON_GetObjectItem(portObject, "request_period");
        if (portObjectRequestPeriod != NULL)
            m_NetworkPortScan.m_nRequestPeriod = portObjectRequestPeriod->valueint;

        cJSON* portObjectRequestCount = cJSON_GetObjectItem(portObject, "count");
        if (portObjectRequestCount != NULL)
            m_NetworkPortScan.m_nRequestCount = portObjectRequestCount->valueint;

        return TRUE;
    }
    BOOL ReadNetworkSensitivePort(cJSON* jsonObject)
    {
        cJSON* sensitiveObject = cJSON_GetObjectItem(jsonObject, "sensitive_port");
        if (sensitiveObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect network sensitive failed");
            return FALSE;
        }

        m_NetworkSensitivePort.ReadNode_TerminateEx(sensitiveObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_LOCKING_TIME);
        m_NetworkSensitivePort.ReadSubNode_Items(sensitiveObject, "list");

        return TRUE;
    }
    BOOL ReadNetworkGatewayProtect(cJSON* jsonObject)
    {
        BOOL bRet = FALSE;

        cJSON* pcJSONGatewayProtect = NULL;
        cJSON* pcJSONGatewayProtectList = NULL;
        cJSON* pcJSONGatewayProtectListItem = NULL;
        cJSON* pcJSONGatewayProtectListItemGateway = NULL;
        cJSON* pcJSONGatewayProtectListItemMac = NULL;
        int nCount = 0;
        std::wstring wstrGateway;
        std::wstring wstrMac;


        do
        {
            m_NetworkGatewayProtect.m_GatewayList.m_vctData.clear();

            if (NULL == jsonObject)
            {
                break;
            }

            pcJSONGatewayProtect = cJSON_GetObjectItem(jsonObject, "gateway_protect");
            if (NULL == pcJSONGatewayProtect)
            {
                break;
            }

            m_NetworkGatewayProtect.ReadNode_TerminateEx(pcJSONGatewayProtect, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_LOCKING_TIME);

            if (!m_NetworkGatewayProtect.nGetEnable())
            {
                break;
            }

            pcJSONGatewayProtectList = cJSON_GetObjectItem(pcJSONGatewayProtect, "list");
            if (NULL == pcJSONGatewayProtectList)
            {
                break;
            }

            nCount = cJSON_GetArraySize(pcJSONGatewayProtectList);
            if (0 == nCount)
            {
                break;
            }

            for (int nIndex = 0; nIndex < nCount; nIndex++)
            {
                pcJSONGatewayProtectListItem = cJSON_GetArrayItem(pcJSONGatewayProtectList, nIndex);
                if (NULL != pcJSONGatewayProtectListItem)
                {
                    pcJSONGatewayProtectListItemGateway = cJSON_GetObjectItem(pcJSONGatewayProtectListItem, "gateway");
                    if (NULL != pcJSONGatewayProtectListItemGateway)
                    {
                        wstrGateway = CPykMgrTemplate<CP_UTF8>(pcJSONGatewayProtectListItemGateway->valuestring);
                    }
                    else
                    {
                        wstrGateway = L"";
                    }

                    pcJSONGatewayProtectListItemMac = cJSON_GetObjectItem(pcJSONGatewayProtectListItem, "mac");
                    if (NULL != pcJSONGatewayProtectListItemMac)
                    {
                        wstrMac = CPykMgrTemplate<CP_UTF8>(pcJSONGatewayProtectListItemMac->valuestring);
                    }
                    else
                    {
                        wstrMac = L"";
                    }

                    m_NetworkGatewayProtect.m_GatewayList.m_vctData.push_back(CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtectListNode(wstrGateway, wstrMac));
                }
            }

            bRet = TRUE;
        } while (FALSE);

        return bRet;
    }

    BOOL ReadAccountLocalLogin(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Local Login Enter");

        cJSON* pLocal = cJSON_GetObjectItem(jsonObject, "local");
        if (pLocal == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account local failed");
            return FALSE;
        }
        m_ntSystemAccountLoginLocal.ReadNode_TerminateEx(pLocal, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);

        cJSON* pTerminateMode = cJSON_GetObjectItem(pLocal, "terminate_mode");
        if (pTerminateMode == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account local terminate_mode failed");
        else
            m_ntSystemAccountLoginLocal.m_nTerminateMode = pTerminateMode->valueint;

        cJSON* pTime = cJSON_GetObjectItem(pLocal, "time");
        if (pTime == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account local time failed");
            return FALSE;
        }

        cJSON* pTimeEnable = cJSON_GetObjectItem(pTime, "enable");
        if (pTimeEnable == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account local time enable failed");
            return FALSE;
        }
        m_ntSystemAccountLoginLocal.m_nTimeEnable = pTimeEnable->valueint;

        m_ntSystemAccountLoginLocal.m_npiTimelist.Clear();
        cJSON* pTimeList = cJSON_GetObjectItem(pTime, "list");
        if (pTimeList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account local time list failed");
            return FALSE;
        }

        int nTimeListNum = cJSON_GetArraySize(pTimeList);
        if (nTimeListNum > 0)
        {
            m_ntSystemAccountLoginLocal.m_npiTimelist.m_nItemNum = nTimeListNum;

            for (int i = 0; i < nTimeListNum; i++)
            {
                cJSON* pListItem = cJSON_GetArrayItem(pTimeList, i);
                cJSON* pItemStart = cJSON_GetObjectItem(pListItem, "start_time");
                std::string strStart = pItemStart->valuestring;
                cJSON* pItemEnd = cJSON_GetObjectItem(pListItem, "end_time");
                std::string strEnd = pItemEnd->valuestring;
                if (strEnd == "00:00")
                    strEnd = "24:00";
                m_ntSystemAccountLoginLocal.m_npiTimelist.m_vctData.push_back
                (CMSBasicInfo_NGEPConfigNode_BeginAndEndTime(strStart, strEnd));
            }
        }
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Local Login Leave");
        return TRUE;
    }

    // 远程登录
    BOOL ReadAccountRemoteLogin(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Remote Login Enter");

        cJSON* pRemote = cJSON_GetObjectItem(jsonObject, "remote");
        if (pRemote == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote failed");
            return FALSE;
        }

        m_ntSystemAccountLoginRemote.ReadNode_TerminateEx(pRemote, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        cJSON* pTerminateMode = cJSON_GetObjectItem(pRemote, "terminate_mode");
        if (pTerminateMode == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote terminate_mode failed");
        else
            m_ntSystemAccountLoginRemote.m_nTerminateMode = pTerminateMode->valueint;

        // 时间
        cJSON* pTime = cJSON_GetObjectItem(pRemote, "time");
        if (pTime == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote time failed");
            return FALSE;
        }

        cJSON* pTimeEnable = cJSON_GetObjectItem(pTime, "enable");
        if (pTimeEnable == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote time enable failed");
            return FALSE;
        }

        m_ntSystemAccountLoginRemote.m_nTimeEnable = pTimeEnable->valueint;

        m_ntSystemAccountLoginRemote.m_npiTimelist.Clear();
        cJSON* pTimeList = cJSON_GetObjectItem(pTime, "list");
        if (pTimeList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote time list failed");
            return FALSE;
        }


        int nTimeListNum = cJSON_GetArraySize(pTimeList);
        if (nTimeListNum > 0)
        {
            m_ntSystemAccountLoginRemote.m_npiTimelist.m_nItemNum = nTimeListNum;
            for (int i = 0; i < nTimeListNum; i++)
            {
                cJSON* pListItem = cJSON_GetArrayItem(pTimeList, i);
                cJSON* pItemStart = cJSON_GetObjectItem(pListItem, "start_time");
                std::string strStart = pItemStart->valuestring;
                cJSON* pItemEnd = cJSON_GetObjectItem(pListItem, "end_time");
                std::string strEnd = pItemEnd->valuestring;
                if (strEnd == "00:00")
                    strEnd = "24:00";

                m_ntSystemAccountLoginRemote.m_npiTimelist.m_vctData.push_back(
                    CMSBasicInfo_NGEPConfigNode_BeginAndEndTime(strStart, strEnd));
            }
        }

        // 地点
        cJSON* pLocation = cJSON_GetObjectItem(pRemote, "location");
        if (pLocation == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote Location failed");
            return FALSE;
        }

        cJSON* pLocationEnable = cJSON_GetObjectItem(pLocation, "enable");
        if (pLocationEnable == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote Location failed");
            return FALSE;
        }
        m_ntSystemAccountLoginRemote.m_nLocationEnable = pLocationEnable->valueint;

        m_ntSystemAccountLoginRemote.m_npiLocationlist.Clear();
        cJSON* pLocationList = cJSON_GetObjectItem(pLocation, "list");
        if (pLocationList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account remote Location List failed");
            return FALSE;
        }


        int nLocationListNum = cJSON_GetArraySize(pLocationList);
        if (nLocationListNum > 0)
        {
            m_ntSystemAccountLoginRemote.m_npiLocationlist.m_nItemNum = nLocationListNum;

            for (int i = 0; i < nLocationListNum; i++)
            {
                cJSON* pListItem = cJSON_GetArrayItem(pLocationList, i);
                cJSON* pItemProvince = cJSON_GetObjectItem(pListItem, "province");
                std::string strProvince = pItemProvince->valuestring;
                cJSON* pItemCity = cJSON_GetObjectItem(pListItem, "city");
                std::string strCity = pItemCity->valuestring;
                m_ntSystemAccountLoginRemote.m_npiLocationlist.m_vctData.push_back(
                    CMSBasicInfo_NGEPConfigNode_Location(strProvince, strCity));
            }
        }
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Remote Login Leave");
        return TRUE;
    }

    // 暴力密码破解
    BOOL ReadAccountCrack(cJSON* jsonObject)
    {
        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Crack Enter");
        cJSON* pCrack = cJSON_GetObjectItem(jsonObject, "crack");
        if (pCrack == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account crack failed");
            return FALSE;
        }
        m_ntSystemAccountCrack.ReadNode_TerminateEx(pCrack, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_LOCKING_TIME);
        // 多少分钟
        cJSON* pInterval = cJSON_GetObjectItem(pCrack, "interval");
        if (pInterval == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account crack pInterval failed");
        else
            m_ntSystemAccountCrack.m_nInterval = pInterval->valueint;

        // 登陆次数
        cJSON* pLimit = cJSON_GetObjectItem(pCrack, "limit");
        if (pLimit == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account crack pLimit failed");
        else
            m_ntSystemAccountCrack.m_nLimit = pLimit->valueint;

        WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Account Crack Leave");
        return TRUE;
    }

    BOOL ReadSensitiveRegedit(cJSON* jsonObject)
    {
        cJSON* regeditObject = cJSON_GetObjectItem(jsonObject, "regedit_change");
        if (regeditObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit failed");
            return FALSE;
        }

        m_SensitiveRegedit.ReadNode_TerminateEx(regeditObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        //cJSON* regeditObjectEnable = cJSON_GetObjectItem(regeditObject, "enable");
        //if (regeditObjectEnable != NULL)
        //{
        // m_SensitiveRegedit.nEnable = regeditObjectEnable->valueint;
        //}

        // 共享内存

        m_SensitiveRegedit.Clear();
        cJSON* regeditObjectList = cJSON_GetObjectItem(regeditObject, "list");
        if (regeditObjectList == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit list failed");
        else
        {
            int nRegListNum = cJSON_GetArraySize(regeditObjectList);
            m_SensitiveRegedit.m_nItemNum = nRegListNum;
            if (nRegListNum == 0)
                return FALSE;
            for (int i = 0; i < nRegListNum; i++)
            {
                CMSBasicInfo_NGEPPolicyNode_Regedit pTemp;
                cJSON* jsonRegItems = cJSON_GetArrayItem(regeditObjectList, i);
                if (jsonRegItems == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit array item failed");
                    return FALSE;
                }

                cJSON* jsonItemsName = cJSON_GetObjectItem(jsonRegItems, "name");
                if (jsonItemsName == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit jsonItemsName failed");
                    continue;
                }
                pTemp.m_strRegName = jsonItemsName->valuestring;

                cJSON* jsonItemsPath = cJSON_GetObjectItem(jsonRegItems, "path");
                if (jsonItemsPath == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit jsonItemsPath failed");
                    continue;
                }
                pTemp.m_strRegPath = jsonItemsPath->valuestring;

                cJSON* jsonItemsValue = cJSON_GetObjectItem(jsonRegItems, "value");
                if (jsonItemsValue == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit jsonItemsValue failed");
                    continue;
                }
                pTemp.m_strRegValue = jsonItemsValue->valuestring;

                cJSON* jsonItemsStatus = cJSON_GetObjectItem(jsonRegItems, "status");
                if (jsonItemsStatus == NULL)
                {
                    WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive regedit jsonItemsStatus failed");
                    continue;
                }
                pTemp.m_nStatus = jsonItemsStatus->valueint;
                m_SensitiveRegedit.m_vctData.push_back(pTemp);
            }
        }

        return TRUE;
    }

    //文件防篡改
    BOOL ReadSensitiveFileSafe(cJSON* jsonObject)
    {
        cJSON* fileObject = cJSON_GetObjectItem(jsonObject, "file_safe");
        if (fileObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive file safe failed");
            return FALSE;
        }
        m_SensitiveFileSafe.ReadNode_TerminateEx(fileObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_SensitiveFileSafe.Clear();
        cJSON* fileObjectList = cJSON_GetObjectItem(fileObject, "list");
        if (fileObjectList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive file list failed");
            return FALSE;
        }

        int nItemsNum = cJSON_GetArraySize(fileObjectList);
        m_SensitiveFileSafe.m_nItemNum = nItemsNum;
        if (nItemsNum == 0)
            return TRUE;
        for (int i = 0; i < nItemsNum; i++)
        {
            CMSBasicInfo_NGEPPolicyNode_FileSafe pTemp;
            cJSON* Items = cJSON_GetArrayItem(fileObjectList, i);
            cJSON* ItemsPath = cJSON_GetObjectItem(Items, "path");
            if (ItemsPath == NULL)
                continue;;

            pTemp.m_strPath = ItemsPath->valuestring;
            pTemp.m_niFileName.ReadSubNode_Items(Items, "name");
            pTemp.m_niProcessName.ReadSubNode_Items(Items, "process");

            // 操作 add添加、delete删除、modify修改
            cJSON* ItemsOperation = cJSON_GetObjectItem(Items, "operation");
            if (ItemsOperation != NULL)
            {
                int nOperation = cJSON_GetArraySize(ItemsOperation);
                for (int k = 0; k < nOperation; k++)
                {
                    cJSON* jsonOperation = cJSON_GetArrayItem(ItemsOperation, k);
                    std::string strT = jsonOperation->valuestring;
                    pTemp.m_eventOperation.SetEvent(strT);
                }
            }
            // 状态
            cJSON* ItemsStatus = cJSON_GetObjectItem(Items, "status");
            if (ItemsStatus != NULL)
                pTemp.m_nStatus = ItemsStatus->valueint;

            cJSON* ItemsID = cJSON_GetObjectItem(Items, "id");
            if (ItemsID != NULL)
                pTemp.m_nID = ItemsID->valueint;
            m_SensitiveFileSafe.m_vctData.push_back(pTemp);
        }
        return TRUE;
    }
    BOOL ReadUSBFileMonitor(cJSON* jsonObject)
    {
        cJSON* fileObject = cJSON_GetObjectItem(jsonObject, "file_usb");
        if (fileObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read USB file failed");
            return FALSE;
        }
        m_USBFileMonitor.ReadNode_TerminateEx(fileObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_USBFileMonitor.ReadSubNode_Items(fileObject, "extension");
        return TRUE;
    }
    BOOL ReadMiddlewareVerify(cJSON* jsonObject)
    {
        cJSON* middlewareObject = cJSON_GetObjectItem(jsonObject, "middleware");
        if (middlewareObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive middleware failed");
            return FALSE;
        }

        m_MiddleFileIdentify.ReadNode_TerminateEx(middlewareObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        m_MiddleFileIdentify.m_niTarget.ReadSubNode_Items(middlewareObject, "target");
        cJSON* middlewareScript = cJSON_GetObjectItem(middlewareObject, "script_files");
        if (middlewareScript == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive middleware script_files failed");
            return FALSE;
        }
        m_MiddleFileIdentify.m_ScriptFile.ReadNode_TerminateEx(middlewareScript, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        m_MiddleFileIdentify.m_ScriptFile.ReadSubNode_Items(middlewareScript, "extension");
        cJSON* middlewarePE = cJSON_GetObjectItem(middlewareObject, "executable_files");
        if (middlewarePE == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive middleware executable_files failed");
            return FALSE;
        }
        m_MiddleFileIdentify.m_PEFile.ReadNode_TerminateEx(middlewarePE, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        cJSON* peExclude = cJSON_GetObjectItem(middlewarePE, "exclude");
        if (peExclude != NULL)
            m_MiddleFileIdentify.m_PEFile.m_nExclude = peExclude->valueint;
        m_MiddleFileIdentify.m_PEFile.ReadSubNode_Items(middlewarePE, "exclude_extension");
        return TRUE;
    }

    BOOL ReadIllegalScriptVerify(cJSON* jsonObject)
    {
        cJSON* backDoorObject = cJSON_GetObjectItem(jsonObject, "backdoor");
        if (backDoorObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect back door failed");
            return FALSE;
        }

        cJSON* backDoorEnable = cJSON_GetObjectItem(backDoorObject, "enable");
        if (backDoorEnable != NULL)
            m_IllegalScriptIdentify.m_nBackDoor = backDoorEnable->valueint;

        cJSON* illegalScriptObject = cJSON_GetObjectItem(backDoorObject, "illegal_script_files");
        if (illegalScriptObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect sensitive illegal script failed");
            return FALSE;
        }

        m_IllegalScriptIdentify.ReadNode_TerminateEx(illegalScriptObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        cJSON* illegalScriptUseKeyword = cJSON_GetObjectItem(illegalScriptObject, "use_default_keyword");
        if (illegalScriptUseKeyword != NULL)
            m_IllegalScriptIdentify.m_nUseKeyword = illegalScriptUseKeyword->valueint; // 是否系统系统审查库 1 是, 0 否 5.0.5 开关移除，默认为 0
        m_IllegalScriptIdentify.m_niTargetData.Clear();
        cJSON* TargetList = cJSON_GetObjectItem(illegalScriptObject, "target");
        if (TargetList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Illegal Target failed");
            return FALSE;
        }
        int nTargetNum = cJSON_GetArraySize(TargetList);
        m_IllegalScriptIdentify.m_niTargetData.m_nItemNum = nTargetNum;
        if (nTargetNum == 0)
            return FALSE;

        for (int i = 0; i < nTargetNum; i++)
        {
            CMSBasicInfo_NGEPPolicyNode_LogCollector pTemp;
            cJSON* jsonPathExtItems = cJSON_GetArrayItem(TargetList, i);
            if (jsonPathExtItems == NULL)
            {
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Illegal Target failed jsonPathExtItems");
                return FALSE;
            }
            pTemp.ReadNode_LogCollector(jsonPathExtItems, "path", "extension");
            m_IllegalScriptIdentify.m_niTargetData.m_vctData.push_back(pTemp);
        }

        // 脚本文件 自定义关键字
        m_IllegalScriptIdentify.m_niDefaultkeyword.ReadSubNode_Items(illegalScriptObject, "default_keyword");
        m_IllegalScriptIdentify.m_niCustomKeyword.ReadSubNode_Items(illegalScriptObject, "keyword");
        return TRUE;
    }
    BOOL ReadWebshellVerify(cJSON* jsonObject)
    {
        cJSON* backDoorObject = cJSON_GetObjectItem(jsonObject, "backdoor");
        if (backDoorObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect back door failed");
            return FALSE;
        }

        cJSON* backDoorEnable = cJSON_GetObjectItem(backDoorObject, "enable");
        if (backDoorEnable != NULL)
            m_WebshellFileIdentify.m_nBackDoor = backDoorEnable->valueint;

        cJSON* webshellObject = cJSON_GetObjectItem(backDoorObject, "webshell_detect");
        if (webshellObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read webshell file script failed");
            return FALSE;
        }
        m_WebshellFileIdentify.ReadNode_TerminateEx(webshellObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);

        cJSON* webshellDefaultRule = cJSON_GetObjectItem(webshellObject, "use_default_rule");
        if (webshellDefaultRule != NULL)
            m_WebshellFileIdentify.m_nUseDefaultRule = webshellDefaultRule->valueint; // 是否使用系统规则库

        cJSON* webshellDetectMode = cJSON_GetObjectItem(webshellObject, "detect_mode");
        if (webshellDetectMode != NULL)
            m_WebshellFileIdentify.m_nDetectMode = webshellDetectMode->valueint; // 1宽松模式 2严格模式

        cJSON* webshellDetectEngine = cJSON_GetObjectItem(webshellObject, "detect_engine");
        if (webshellDetectEngine != NULL)
            m_WebshellFileIdentify.m_nDetectEngine = webshellDetectEngine->valueint; // 1 正则检测 2 统计检测 3 哈希检测 4 机器学习检测 预留以后使用

        m_WebshellFileIdentify.m_niTargetData.Clear();
        cJSON* TargetList = cJSON_GetObjectItem(webshellObject, "target");
        if (TargetList == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Webshell Target failed");
            return FALSE;
        }

        int nTargetNum = cJSON_GetArraySize(TargetList);
        m_WebshellFileIdentify.m_niTargetData.m_nItemNum = nTargetNum;
        if (nTargetNum == 0)
            return FALSE;
        for (int i = 0; i < nTargetNum; i++)
        {
            CMSBasicInfo_NGEPPolicyNode_LogCollector pTemp;
            cJSON* jsonPathExtItems = cJSON_GetArrayItem(TargetList, i);
            if (jsonPathExtItems == NULL)
            {
                WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Webshell Target failed jsonPathExtItems");
                return FALSE;
            }
            pTemp.ReadNode_LogCollector(jsonPathExtItems, "path", "extension");
            m_WebshellFileIdentify.m_niTargetData.m_vctData.push_back(pTemp);
        }
        return TRUE;
    }

    BOOL ReadSystemResource(cJSON* jsonObject)
    {
        cJSON* sysObject = cJSON_GetObjectItem(jsonObject, "sys");
        if (sysObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read System Resource find sys NULL return");
            return FALSE;
        }
        m_SysResourceEnable.ReadNode_TerminateEx(sysObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);



        // 内存
        cJSON* memObject = cJSON_GetObjectItem(sysObject, "memory");
        if (memObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read System Resource memory NULL");
        else
            pFunReadResourceNode(memObject, m_SysResourceMem);

        // CPU
        cJSON* cpuObject = cJSON_GetObjectItem(sysObject, "cpu");
        if (cpuObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read System Resource cpu NULL");
        else
            pFunReadResourceNode(cpuObject, m_SysResourceCPU);

        //disk
        cJSON* diskObject = cJSON_GetObjectItem(sysObject, "disk");
        if (diskObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read System Resource disk NULL");
        else
            pFunReadResourceNode(diskObject, m_SysResourceDisk);

        //network
        cJSON* netflowObject = cJSON_GetObjectItem(sysObject, "netflow");
        if (netflowObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read System Resource net flow NULL");
        else
        {
            m_SysResourceNet.ReadNode_TerminateEx(netflowObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
            cJSON* netflowInterval = cJSON_GetObjectItem(netflowObject, "interval");
            if (netflowInterval != NULL)
                m_SysResourceNet.m_nInterval = netflowInterval->valueint;

            cJSON* netflowDown = cJSON_GetObjectItem(netflowObject, "down");
            if (netflowDown != NULL)
                m_SysResourceNet.m_nDownFlow = netflowDown->valueint;

            cJSON* netflowUp = cJSON_GetObjectItem(netflowObject, "up");
            if (netflowUp != NULL)
                m_SysResourceNet.m_nUpFlow = netflowUp->valueint;
        }
        return TRUE;
    }
    BOOL ReadProcessResource(cJSON* jsonObject)
    {
        cJSON* processObject = cJSON_GetObjectItem(jsonObject, "process");
        if (processObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Process Resource find process NULL return");
            return FALSE;
        }

        m_ProcessResourceEnable.ReadNode_TerminateEx(processObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        //auto pFunReadResourceNode1 = [](cJSON* jsonNode, CMSBasicInfo_NGEPConfigNode_AccountCrack& node)
        //{
        // node.ReadNode_TerminateEx(jsonNode, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        // cJSON* memLimit = cJSON_GetObjectItem(jsonNode, "limit");
        // if (memLimit != NULL)
        // node.m_nLimit = memLimit->valueint;
        // cJSON* memInterval = cJSON_GetObjectItem(jsonNode, "interval");
        // if (memInterval != NULL)
        // node.m_nInterval = memInterval->valueint;
        //};

        // 内存
        cJSON* memObject = cJSON_GetObjectItem(processObject, "memory");
        if (memObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Process Resource memory NULL");
        else
            pFunReadResourceNode(memObject, m_ProcessResourceMem);

        // CPU
        cJSON* cpuObject = cJSON_GetObjectItem(processObject, "cpu");
        if (cpuObject == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read Process Resource cpu NULL");
        else
            pFunReadResourceNode(cpuObject, m_ProcessResourceCPU);

        return TRUE;
    }

    BOOL ReadNewPolicyUSBPrinterCDRom(cJSON* jsonObject, char* szDeviceType, CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems& DeviceType)
    {
        cJSON* deviceObject = cJSON_GetObjectItem(jsonObject, szDeviceType);
        if (deviceObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read fasten device failed");
            return FALSE;
        }
        DeviceType.ReadNode_TerminateEx(deviceObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE | CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_TERMINATE);
        cJSON* deviceArray = NULL;
        if (_stricmp(szDeviceType, "USB") == 0)
            deviceArray = cJSON_GetObjectItem(deviceObject, "exclude");
        else
            deviceArray = cJSON_GetObjectItem(deviceObject, "extension");

        if (deviceArray == NULL)
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read protect fasten usb exclude failed");
        else
            DeviceType.ReadNode_Items(deviceArray);
        return TRUE;
    }
    BOOL ReadNewExcludeUUID(cJSON* jsonObject)
    {
        cJSON* excludeObject = cJSON_GetObjectItem(jsonObject, "exclude_uuid");
        if (excludeObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read fasten exclude uuid failed");
            return FALSE;
        }
        m_FastenExclude.ReadNode_Items(excludeObject);
        return TRUE;
    }

    BOOL ReadNewPolicyDeviceOther(cJSON* jsonObject, char* chDeviceType, CMSBasicInfo_NGEPConfigNode_OtherDevice& DeviceType)
    {
        cJSON* deviceObject = cJSON_GetObjectItem(jsonObject, chDeviceType);
        if (deviceObject == NULL)
        {
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "Read fasten device failed");
            return FALSE;
        }

        DeviceType.ReadNode_TerminateEx(deviceObject, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        cJSON* serialportObject = cJSON_GetObjectItem(deviceObject, "serialport");
        if (serialportObject != NULL)
            DeviceType.m_nSerialport = serialportObject->valueint;
        cJSON* parallelportObject = cJSON_GetObjectItem(deviceObject, "parallelport");
        if (parallelportObject != NULL)
            DeviceType.m_nParallelport = parallelportObject->valueint;
        cJSON* infraredObject = cJSON_GetObjectItem(deviceObject, "infrared");
        if (infraredObject != NULL)
            DeviceType.m_nInfrared = infraredObject->valueint;
        cJSON* h1394Object = cJSON_GetObjectItem(deviceObject, "h1394");
        if (h1394Object != NULL)
            DeviceType.m_nH1394 = h1394Object->valueint;
        cJSON* bluetoothObject = cJSON_GetObjectItem(deviceObject, "bluetooth");
        if (bluetoothObject != NULL)
            DeviceType.m_nBluetooth = bluetoothObject->valueint;
        cJSON* cdromObject = cJSON_GetObjectItem(deviceObject, "cdrom");
        if (cdromObject != NULL)
            DeviceType.m_nCDROM = cdromObject->valueint;
        return TRUE;
    }


    void pFunReadResourceNode(cJSON* jsonNode, CMSBasicInfo_NGEPConfigNode_AccountCrack& node)
    {
        node.ReadNode_TerminateEx(jsonNode, CMSBasicInfo_NGEPConfigNode_Terminate::MSBI_NP_TE_F_ENABLE);
        cJSON* memLimit = cJSON_GetObjectItem(jsonNode, "limit");
        if (memLimit != NULL)
            node.m_nLimit = memLimit->valueint;

        cJSON* memInterval = cJSON_GetObjectItem(jsonNode, "interval");
        if (memInterval != NULL)
            node.m_nInterval = memInterval->valueint;
    };
public:

    CMSBasicInfo_NGEPPolicy_Common m_NGEPPolicy_Common;

    //挖矿
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntBehaviourMining;
    //ETW勒索
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_netwBehaviourRansomwareETWDATA;
    //恶意行为-勒索行为
    CMSBasicInfo_NGEPConfigNode_MinifilterData m_nminiBehaviourRansomwareMinifilter;

    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessReverseShell;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessPrivilege;
    //进程异常-MBR防护
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessMBR;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessCommand;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessWebshell;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessService;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessFakeSys;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessTunnel;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessRiskCommand;
    CMSBasicInfo_NGEPConfigNode_Terminate m_ntProcessAbnormalProcess;
    CMSCFG_NGEPConfigNode_Items<std::string> m_niProcessCommandTable;

    CMSBasicInfo_NGEPConfigNode_Terminate m_ntNetworkDomain;
    CMSBasicInfo_NGEPConfigNode_NetworkIllegalConnect m_nicNetworkIllegalConnect;
    CMSBasicInfo_NGEPConfigNode_NetworkPortScan m_NetworkPortScan;
    CMSBasicInfo_NGEPConfigNode_NetworkSensitivePort m_NetworkSensitivePort;
    CMSBasicInfo_NGEPConfigNode_NetworkGatewayProtect m_NetworkGatewayProtect;

    CMSBasicInfo_NGEPConfigNode_Terminate m_ntSystemAccountLogin;
    CMSBasicInfo_NGEPConfigNode_AccountLocal m_ntSystemAccountLoginLocal;
    CMSBasicInfo_NGEPConfigNode_AccountRemote m_ntSystemAccountLoginRemote;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_ntSystemAccountCrack;
    CMSBasicInfo_NGEPConfigNode_Terminate m_SystemAccountAbnormal;
    CMSBasicInfo_NGEPConfigNode_AccountUserChanges m_AccountUserChanges;

    CMSBasicInfo_NGEPConfigNode_Terminate m_SensitiveLogDelete;
    CMSBasicInfo_NGEPPolicyNode_SensitiveRegedit m_SensitiveRegedit;
    //敏感信息-文件防篡改
    CMSBasicInfo_NGEPConfigNode_TerminateAndItems<CMSBasicInfo_NGEPPolicyNode_FileSafe> m_SensitiveFileSafe;
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_USBFileMonitor;
    CMSBasicInfo_NGEPPolicyNode_MiddleFileIdentify m_MiddleFileIdentify;
    CMSBasicInfo_NGEPPolicyNode_IllegalScriptIdentify m_IllegalScriptIdentify;
    CMSBasicInfo_NGEPPolicyNode_WebshellFileIdentify m_WebshellFileIdentify;

    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorProcess;
    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorNework;
    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorNework_dpi;
    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorDNS;
    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorETW;
    CMSBasicInfo_NGEPConfigNode_LogcollectorFile m_LogcollectorFile;
    CMSBasicInfo_NGEPConfigNode_LogcollectorFile m_LogcollectorFile_Open;
    CMSBasicInfo_NGEPConfigNode_Terminate m_LogcollectorAuditPolicy;

    CMSBasicInfo_NGEPConfigNode_Terminate m_ResourceMonitor;
    CMSBasicInfo_NGEPConfigNode_Terminate m_SysResourceEnable;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_SysResourceMem;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_SysResourceCPU;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_SysResourceDisk;
    CMSBasicInfo_NGEPConfigNode_NetFlow m_SysResourceNet;

    CMSBasicInfo_NGEPConfigNode_Terminate m_ProcessResourceEnable;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_ProcessResourceMem;
    CMSBasicInfo_NGEPConfigNode_AccountCrack m_ProcessResourceCPU;
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_FastenUSB;
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_FastenPrinter;
    //外设管理-刻录机监控
    CMSBasicInfo_NGEPConfigNode_TerminateAndStringItems m_FastenCDRom;
    //外设管理-例外主机
    CMSCFG_NGEPConfigNode_Items<std::string> m_FastenExclude;
    CMSBasicInfo_NGEPConfigNode_OtherDevice m_DeviceOther;

    CMSBasicInfo_NGEPConfigNode_Terminate m_OtherUninstall;
    CMSBasicInfo_NGEPConfigNode_Terminate m_OtherShowTray;

    CMSBasicInfo_NGEPConfigNode_Virus m_VirusMonitor;
};