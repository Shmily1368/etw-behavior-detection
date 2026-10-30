
#include "NgepIpcClientApi.h"
#include "../ThirdPart/cJSON/include/cJsonHelper.hpp"
#include "MSTypeConversion.h"

//ipc和非ipc类的统一基类用于统一方法调用
class MSSqlite_LocalOfflineDB_Base
{
public:
    MSSqlite_LocalOfflineDB_Base() {}
    ~MSSqlite_LocalOfflineDB_Base() {}

    virtual bool AddLog(cJSON* pJsonRoot) = 0;

    static constexpr unsigned char m_xor_Base64Key = 0x21;
private:

};

class MSSqlite_LocalOfflineDB_IPC : public MSSqlite_LocalOfflineDB_Base
{
public:
#ifndef NO_USE_RESOURCE

    MSSqlite_LocalOfflineDB_IPC(std::wstring& strIpcSrc)
    {
#ifdef NGEPIPCCLIENT_NO_USE_LIB
        std::wstring strDllPath;
#ifndef MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S
#ifndef _WIN64
        strDllPath = IMSResourceGetInstance()->Get(MS_ENUM_RESOURCE_ID_DLL_NGEPIPCCLIENT).wstrX86BinaryPathName;
#else
        strDllPath = IMSResourceGetInstance()->Get(MS_ENUM_RESOURCE_ID_DLL_NGEPIPCCLIENT).wstrX64BinaryPathName;
#endif
#else
#ifndef _WIN64
        strDllPath = CMSResource::GetInstance()->m_mapResourceList[MS_ENUM_RESOURCE_ID_DLL_NGEPIPCCLIENT].wstrX86BinaryPathName;
#else
        strDllPath = CMSResource::GetInstance()->m_mapResourceList[MS_ENUM_RESOURCE_ID_DLL_NGEPIPCCLIENT].wstrX64BinaryPathName;
#endif
#endif // MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S
        m_pIpc = GetNgepIpcClientInstance(strIpcSrc, strDllPath);
#else
        m_pIpc = INgepIpcClientGetInstance(strIpcSrc.c_str(), strIpcSrc.length());
#endif // NGEPIPCCLIENT_NO_USE_LIB
    }
#else
    MSSqlite_LocalOfflineDB_IPC(std::wstring& strIpcSrc, std::wstring& strDllPath)
    {
#ifdef NGEPIPCCLIENT_NO_USE_LIB
        m_pIpc = GetNgepIpcClientInstance(strIpcSrc, strDllPath);
#else
        m_pIpc = INgepIpcClientGetInstance(strIpcSrc.c_str(), strIpcSrc.length());
#endif // NGEPIPCCLIENT_NO_USE_LIB
    }

#endif
    ~MSSqlite_LocalOfflineDB_IPC() {}

    bool WriteToOfflineDBByIPC(cJSON* pJsonRoot)
    {
        bool bRet = false;
        do
        {
            if (NULL == m_pIpc)
            {
                break;
            }

            char* szTemp = cJSON_PrintUnformatted(pJsonRoot);
            std::string strT = szTemp;
            WriteLog4cPlusBaseA(DEBUG_LEVEL, "%s", strT.c_str());
            if (szTemp != NULL)
            {
                free(szTemp);
                szTemp = NULL;
            }
            std::string strEncryptTxt = CMSTypeConversion::XorAndBase64String(strT
                , m_xor_Base64Key);
            bRet = (MS_ERROR_SUCCESS == m_pIpc->AddNgepLog(MS_ENUM_IPC_LOG_DSTDB_LOCALOFFLINEDB, strEncryptTxt.c_str(), (int)strEncryptTxt.length()));
        } while (false);
        return bRet;
    }

    BOOL
        WriteToVirusScanCronTaskResultByIPC(
            _In_ CONST cJSON* pJsonRoot
        )
    {
        BOOL bRet = FALSE;

        char* pchJsonText = NULL;
        std::string strJsonTextEncrypt;
        MS_ERROR MsError = MS_ERROR_DEFAULT;


        do
        {
            if (NULL == m_pIpc)
            {
                break;
            }

            pchJsonText = cJSON_PrintUnformatted(pJsonRoot);

            strJsonTextEncrypt = CMSTypeConversion::XorAndBase64String(pchJsonText, m_xor_Base64Key);

            MsError = m_pIpc->AddNgepLog(MS_ENUM_IPC_LOG_DSTDB_VIRUS_SCAN_CRON_TASK_RESULT, strJsonTextEncrypt.c_str(), (int)strJsonTextEncrypt.length());
            if (MS_ERROR_SUCCESS != MsError)
            {
                break;
            }

            bRet = TRUE;
        } while (FALSE);

        if (NULL != pchJsonText)
        {
            free(pchJsonText);
            pchJsonText = NULL;
        }

        return bRet;
    }

    virtual bool AddLog(cJSON* pJsonRoot)
    {
        return WriteToOfflineDBByIPC(pJsonRoot);
    }
private:
    INgepIpcClient* m_pIpc = nullptr;
};