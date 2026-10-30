#include "MSResource.h"
#include "Log4cplusBase.h"

#pragma warning(disable : 4127)

#ifndef MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S
#ifndef MSCOMMONS_EXPORTS
extern "C"
MSCOMMON_API
IMSResource *
WINAPI
IMSResourceGetInstance()
{
    return (IMSResource*)CMSResource::GetInstance();
}

extern "C"
MSCOMMON_API
VOID
WINAPI
IMSResourceReleaseInstance()
{
    CMSResource::ReleaseInstance();
}
#endif
#endif

MS_ERROR
WINAPI
CMSResource::Init()
{
    WriteLog4cPlusBaseW(DEBUG_LEVEL, L"CMSResource::Init");
    MS_ERROR MSError = MS_ERROR_DEFAULT;


    do
    {
        if (!GetInitFlag())
        {
            MSError = CMSPath::GetInstance()->Init();
            if (MS_ERROR_SUCCESS != MSError)
            {
                WriteLog4cPlusBaseA(ERROR_LEVEL, "CMSPath::GetInstance()->Init failed. MSError(%d)", MSError);
                break;
            }

            SetResourceList();

            SetInitFlag(TRUE);
        }

        MSError = MS_ERROR_SUCCESS;
    } while (FALSE);

    if (MS_ERROR_SUCCESS != MSError)
    {
        MSError = Unload();
    }

    return MSError;
}

MS_ERROR
WINAPI
CMSResource::Unload()
{
    MS_ERROR MSError = MS_ERROR_DEFAULT;


    do
    {
        if (GetInitFlag())
        {
            SetInitFlag(FALSE);
        }

        MSError = MS_ERROR_SUCCESS;
    } while (FALSE);

    return MSError;
}

MS_STRUCT_RESOURCE_INFO
WINAPI
CMSResource::Get(
    _In_ CONST MS_ENUM_RESOURCE_ID enumResourceId
)
{
    MS_STRUCT_RESOURCE_INFO ret;


    do
    {
        ret = m_mapResourceList[enumResourceId];
    } while (FALSE);

    return ret;
}

CMSResource::CMSResource()
{
    ;
}

CMSResource::~CMSResource()
{
    ;
}

VOID CMSResource::SetResourceInfo_InInstallDir(_MS_ENUM_RESOURCE_ID nId
    , LPCTSTR lpX86PathName
    , LPCTSTR lpX64PathName)
{
    MS_STRUCT_RESOURCE_INFO structResourceInfo;

    structResourceInfo.enumResourceId = nId;

    structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
    structResourceInfo.wstrX86BinaryPathName += lpX86PathName;

    structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
    structResourceInfo.wstrX64BinaryPathName += lpX64PathName;

    m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
}

VOID CMSResource::SetResourceInfo(_MS_ENUM_RESOURCE_ID nId
    , MS_ENUM_CLIENT_DIRECTORY_TYPE nDirType
    , LPCTSTR lpX86PathName
    , LPCTSTR lpX64PathName)
{
    MS_STRUCT_RESOURCE_INFO structResourceInfo;

    structResourceInfo.enumResourceId = nId;

    structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(nDirType);
    structResourceInfo.wstrX86BinaryPathName += lpX86PathName;

    structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(nDirType);
    structResourceInfo.wstrX64BinaryPathName += lpX64PathName;

    m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
}


VOID
CMSResource::SetResourceList()
{
    do
    {
        for (MS_ENUM_RESOURCE_ID enumResourceId = MS_ENUM_RESOURCE_ID_MIN; enumResourceId < MS_ENUM_RESOURCE_ID_MAX; enumResourceId = (MS_ENUM_RESOURCE_ID)(enumResourceId + 1))
        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = enumResourceId;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_DRIVER_MAGIC_FILE_DRV;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\Drivers\\MagicFileDrv.sys";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\MagicFileDrv.sys";

            structResourceInfo.Service.wstrServiceName = L"MagicFileDrv";
            structResourceInfo.Service.wstrDisplayName = L"MagicFileDrv";
            structResourceInfo.Service.dwServiceType = SERVICE_FILE_SYSTEM_DRIVER;
            structResourceInfo.Service.dwStartType = SERVICE_DEMAND_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;
            structResourceInfo.Service.wstrLoadOrderGroup = L"FSFilter Activity Monitor";

            MoveMemory(structResourceInfo.Service.mstrDependencies, L"FltMgr\0\0", sizeof(L"FltMgr\0\0"));

            structResourceInfo.Service.wstrAltitude = L"360999";

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_DRIVER_MAGIC_PROCESSER_DRV;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\Drivers\\MagicProcesserDrv.sys";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\MagicProcesserDrv.sys";

            structResourceInfo.Service.wstrServiceName = L"MagicProcesser";
            structResourceInfo.Service.wstrDisplayName = L"MagicProcesser";
            structResourceInfo.Service.dwServiceType = SERVICE_KERNEL_DRIVER;
            structResourceInfo.Service.dwStartType = SERVICE_DEMAND_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_DRIVER_MAGIC_REGISTRY_DRV;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\Drivers\\MagicRegistryDrv.sys";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\MagicRegistryDrv.sys";

            structResourceInfo.Service.wstrServiceName = L"MagicRegistryDrv";
            structResourceInfo.Service.wstrDisplayName = L"MagicRegistryDrv";
            structResourceInfo.Service.dwServiceType = SERVICE_KERNEL_DRIVER;
            structResourceInfo.Service.dwStartType = SERVICE_DEMAND_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_DRIVER_WIN_DIVERT;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\Drivers\\WinDivert.sys";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\WinDivert.sys";

            structResourceInfo.Service.wstrServiceName = L"WinDivert";
            structResourceInfo.Service.wstrDisplayName = L"WinDivert";
            structResourceInfo.Service.dwServiceType = SERVICE_KERNEL_DRIVER;
            structResourceInfo.Service.dwStartType = SERVICE_DEMAND_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_DRIVER_MAGIC_NET_DRV;

#if 0
            {
                CMSDisableFsRedirection MSDisableFsRedirection;

                HRESULT hResult = S_FALSE;
                WCHAR wchFolderSystem[MAX_PATH] = { 0 };

                hResult = SHGetFolderPath(
                    NULL,
                    CSIDL_SYSTEM,
                    NULL,
                    SHGFP_TYPE_DEFAULT,
                    wchFolderSystem
                );
                if (S_OK == hResult)
                {
                    structResourceInfo.wstrX86BinaryPathName = wchFolderSystem;
                    structResourceInfo.wstrX86BinaryPathName += L"\\drivers\\MagicNetDrv.sys";

                    structResourceInfo.wstrX64BinaryPathName = wchFolderSystem;
                    structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\MagicNetDrv.sys";
                }
            }
#else
            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\Drivers\\MagicNetDrv.sys";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\Drivers\\MagicNetDrv.sys";
#endif

            structResourceInfo.Service.wstrServiceName = L"MagicNetDrv";
            structResourceInfo.Service.wstrDisplayName = L"MagicNetDrv";
            structResourceInfo.Service.dwServiceType = SERVICE_KERNEL_DRIVER;
            structResourceInfo.Service.dwStartType = SERVICE_DEMAND_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_SERVICE_NGEP_SERVICE;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\NgepService.exe";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\NgepService.exe";

            structResourceInfo.Service.wstrServiceName = L"NgepService";
            structResourceInfo.Service.wstrDisplayName = L"NgepService";
            structResourceInfo.Service.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            structResourceInfo.Service.dwStartType = SERVICE_AUTO_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;
            structResourceInfo.Service.wstrLoadOrderGroup = L"COM Infrastructure";

            MoveMemory(structResourceInfo.Service.mstrDependencies, L"RPCSS\0\0", sizeof(L"RPCSS\0\0"));

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        {
            MS_STRUCT_RESOURCE_INFO structResourceInfo;

            structResourceInfo.enumResourceId = MS_ENUM_RESOURCE_ID_SERVICE_NGEPASSIST_SERVICE;

            structResourceInfo.wstrX86BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX86BinaryPathName += L"\\NgepAssist.exe";

            structResourceInfo.wstrX64BinaryPathName = CMSPath::GetInstance()->Get(MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL);
            structResourceInfo.wstrX64BinaryPathName += L"\\NgepAssist.exe";

            structResourceInfo.Service.wstrServiceName = L"NgepAssist";
            structResourceInfo.Service.wstrDisplayName = L"NgepAssist";
            structResourceInfo.Service.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
            structResourceInfo.Service.dwStartType = SERVICE_AUTO_START;
            structResourceInfo.Service.dwErrorControl = SERVICE_ERROR_NORMAL;

            m_mapResourceList[structResourceInfo.enumResourceId] = structResourceInfo;
        }

        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_CONFIG_NGEP_CUSTOM_CFG
            , L"\\NGEPCustomCfg.ini"
            , L"\\NGEPCustomCfg.ini");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_EXE_PLY_PATCH_EXE
            , L"\\PlyPatchExe.exe"
            , L"\\PlyPatchExe.exe");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_VIRUS_SCAN_SDK
            , L"\\VirusScan\\VirusScanSDK.dll"
            , L"\\VirusScan\\VirusScanSDK64.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MAGIC_DRV_SVR
            , L"\\MagicDrvSvr.dll"
            , L"\\MagicDrvSvr.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MAGIC_NETWORK
            , L"\\MagicNetwork.dll"
            , L"\\MagicNetwork.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MAGIC_PROCESS
            , L"\\MagicProcess.dll"
            , L"\\MagicProcess.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MAGIC_REGISTRY
            , L"\\MagicRegistry.dll"
            , L"\\MagicRegistry.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_CONFIG_NGEP_ASSIST_RECORD
            , L"\\NGEPAssistRecord.ini"
            , L"\\NGEPAssistRecord.ini");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_CONFIG_INFO_DAT
            , L"\\info.dat"
            , L"\\info.dat");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_WINDIVERT
            , L"\\WinDivert.dll"
            , L"\\WinDivert.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_LIB_SSL
            , L"\\libssl-1_1.dll"
            , L"\\libssl-1_1.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_LIB_CRYPTO
            , L"\\libcrypto-1_1.dll"
            , L"\\libcrypto-1_1.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_NF_API
            , L"\\nfapi.dll"
            , L"\\nfapi.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_PROTOCOL_FILTERS
            , L"\\ProtocolFilters.dll"
            , L"\\ProtocolFilters.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MS_CACHE
            , L"\\MSCache.dll"
            , L"\\MSCache.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_PLYWEBSHELL
            , L"\\PlyWebShell.dll"
            , L"\\PlyWebShell.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_NGEPIPCCLIENT
            , L"\\NgepIpcClient.dll"
            , L"\\NgepIpcClient64.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_LOCAL_CONFIG_NGEP
            , L"\\LocalConfig.dat"
            , L"\\LocalConfig.dat");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MAGIC_MIDDLE
            , L"\\MagicMiddle.dll"
            , L"\\MagicMiddle.dll");
		SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_MS_ANT
			, L"\\MSAnt.dll"
			, L"\\MSAnt.dll");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_CONFIG_NGEP_PROCESS_FILTER_CFG
            , L"\\NgepProcessFilter.cfg"
            , L"\\NgepProcessFilter.cfg");
        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_DLL_VIRUS_SCAN_MENU
            , L"\\VirusScan\\VirusScanMenu.dll"
            , L"\\VirusScan\\VirusScanMenu64.dll");

        SetResourceInfo_InInstallDir(
            MS_ENUM_RESOURCE_ID_EXE_NGEP_COLLECT
            , L"\\NgepCollect.exe"
            , L"\\NgepCollect.exe");

        SetResourceInfo_InInstallDir(
            MS_ENUM_RESOURCE_ID_EXE_NGEP_MESSAGER
            , L"\\NgepMessager.exe"
            , L"\\NgepMessager.exe");

        SetResourceInfo_InInstallDir(
            MS_ENUM_RESOURCE_ID_EXE_NGEP_UPDATE
            , L"\\NgepUpdate.exe"
            , L"\\NgepUpdate.exe");

        SetResourceInfo_InInstallDir(
            MS_ENUM_RESOURCE_ID_EXE_UNINST
            , L"\\Uninst.exe"
            , L"\\Uninst.exe");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_LOCALOFFLINEDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_SAFEMONOR
            , L"\\LocalOfflineDb.db"
            , L"\\LocalOfflineDb.db");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_BACKUPDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_BACKUPSQL
            , L"\\Backup.dat"
            , L"\\Backup.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_BACKUPLISTDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_BACKUPSQL
            , L"\\BackupList.dat"
            , L"\\BackupList.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_WEBSHELLVERDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Data\\WebshellVer.dat"
            , L"\\Data\\WebshellVer.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_OFFLINEDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Data\\Offline.dat"
            , L"\\Data\\Offline.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_BASELINEVERDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Data\\BaseLineVer.dat"
            , L"\\Data\\BaseLineVer.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_DB_VIRUS_SCAN_SCANLOGDB
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\VirusScan\\Data\\ScanLog.dat"
            , L"\\VirusScan\\Date\\ScanLog.dat");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_EXE_VIRUS_SCAN
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\VirusScan\\VirusScan.exe"
            , L"\\VirusScan\\VirusScan.exe");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_CONFIG_NGEP_POLICY
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Nacvf.lst"
            , L"\\Nacvf.lst");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_CONFIG_NGEP_RULE
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Narlf.lst"
            , L"\\Narlf.lst");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_CONFIG_ETW_VERSION
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_ETW
            , L"\\Version.ini"
            , L"\\Version.ini");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_SSL_CRT
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Data\\client.crt"
            , L"\\Data\\client.crt");

        SetResourceInfo(
            MS_ENUM_RESOURCE_ID_SSL_KEY
            , MS_ENUM_CLIENT_DIRECTORY_TYPE_INSTALL
            , L"\\Data\\client.key"
            , L"\\Data\\client.key");

        SetResourceInfo_InInstallDir(MS_ENUM_RESOURCE_ID_CONFIG_NEW_INFO_DAT
            , L"\\new_info.dat"
            , L"\\new_info.dat");
    } while (FALSE);

    return;
}
