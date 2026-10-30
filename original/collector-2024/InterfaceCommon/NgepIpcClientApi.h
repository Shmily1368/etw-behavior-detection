
#pragma once
#define NGEPIPCCLIENT_NO_USE_LIB

#ifdef NGEPIPCCLIENT_NO_USE_LIB
#include "Log4cplusBase.h"
#include "MSError.h"
#include"MSEnum.h"
//#include "MSResource.h"
#endif // NGEPIPCCLIENT_NO_USE_LIB


#ifdef NGEPIPCCLIENT_EXPORTS
#define NGEPIPCCLIENT_API __declspec(dllexport)
#else
#define NGEPIPCCLIENT_API __declspec(dllimport)
#ifndef NGEPIPCCLIENT_NO_USE_LIB

#ifdef _DEBUG
#ifndef _WIN64
#pragma comment(lib, "Debug\\win32\\NgepIpcClient.lib")
#else
#pragma comment(lib, "Debug\\x64\\NgepIpcClient.lib")
#endif
#else
#ifndef _WIN64
#pragma comment(lib, "Release\\win32\\NgepIpcClient.lib")
#else
#pragma comment(lib, "Release\\x64\\NgepIpcClient.lib")
#endif
#endif

#endif // !NGEPIPCCLIENT_NO_USE_LIB
#endif

#ifndef MIDL_INTERFACE
#define MIDL_INTERFACE(x) struct DECLSPEC_UUID(x) DECLSPEC_NOVTABLE
#endif

#ifndef BEGIN_INTERFACE
#define BEGIN_INTERFACE
#endif

#ifndef END_INTERFACE
#define END_INTERFACE
#endif

#ifndef __INgepIpcClient_INTERFACE_DEFINED__
#define __INgepIpcClient_INTERFACE_DEFINED__
struct INgepIpcClient
{
public:
    virtual
        MS_ERROR
        WINAPI
        StopMagicFileDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        StopMagicRegistryDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        StopMagicProcesser() = 0;

    virtual
        MS_ERROR
        WINAPI
        StopWinDivert() = 0;

    virtual
        MS_ERROR
        WINAPI
        StartMagicFileDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        StartMagicRegistryDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        StartMagicProcesser() = 0;

    virtual
        MS_ERROR
        WINAPI
        StartWinDivert() = 0;

    virtual
        MS_ERROR
        WINAPI
        StopClient() = 0;

    virtual
        MS_ERROR
        WINAPI
        QueryMagicFilePauseState(int/*MS_ENUM_IPC_MESSAGE_TYPE_QUERY_PAUSE_STATE_RESULT*/* bResult) = 0;

    virtual
        MS_ERROR
        WINAPI
        QueryMagicProcessPauseState(int* bResult) = 0;

    virtual
        MS_ERROR
        WINAPI
        QueryMagicRegistryPauseState(int* bResult) = 0;

    virtual
        MS_ERROR
        WINAPI
        QueryMagicNetworkPauseState(int* bResult) = 0;

    virtual
        MS_ERROR
        WINAPI
        PauseMagicFileDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        PauseMagicRegistryDrv() = 0;

    virtual
        MS_ERROR
        WINAPI
        PauseMagicProcesser() = 0;

    virtual
        MS_ERROR
        WINAPI
        PauseWinDivert() = 0;

    virtual
        MS_ERROR
        WINAPI
        AddNgepLog(const MS_ENUM_IPC_LOG_DSTDB nType, const char* szLogData,const int nLogDataSize) = 0;
    virtual
        MS_ERROR
        WINAPI
        AddNgepUploadSample(const char* szLogData, const int nLogDataSize
            , const char* szFilePath, const int nFilePathSize
            , const char* szFileMd5Data, const int nFileMd5Size) = 0;

    virtual
        MS_ERROR
        WINAPI
        CloseFile(
            _In_ CONST WCHAR* pwchFilePath,
            _In_ CONST int nLengthCh
        )
    {
        UNREFERENCED_PARAMETER(pwchFilePath);
        UNREFERENCED_PARAMETER(nLengthCh);
    
        return MS_ERROR_NOT_SUPPORT;
    }

    virtual
        MS_ERROR
        WINAPI
        LockHost() = 0;

    virtual
        MS_ERROR
        WINAPI
        UnLockHost() = 0;

    virtual
        MS_ERROR
        WINAPI
        RunInteractiveProcess(const char* szProcessPath, const int nProcessPathLength
            , const char* szCommand, const int nCommandLength) = 0;

    virtual
        MS_ERROR
        WINAPI
        RunAdminProcess(const char* szProcessPath, const int nProcessPathLength
            , const char* szCommand, const int nCommandLength
            , __int64 nUser, __int64 nSessionId) = 0;
    virtual
        MS_ERROR
        WINAPI
        QueryOnlineAndHeartData(char* szOnlineTime, unsigned int nOnlineTimeLength
            , char* szHeartTime, unsigned int nHeartTimeLength) = 0;
    virtual
        MS_ERROR
        WINAPI
        UpdateFile(const char* szSrcFile, const int nSrcFileLength
            , const char* szDstFile, const int nDstFileLength) = 0;
    virtual
        MS_ERROR
        WINAPI
        SaveIniProfile(const char* szIniPath, const int nIniPathLength
            , const char* szSectionName, const int nSectionNameLength
            , const char* szFieldName, const int nFieldNameLength
            , const char* szFieldValue, const int nFieldValueLength
        ) = 0;
};

#define INgepIpcClientGetInstance NGEP_F2991C0F

extern "C"
NGEPIPCCLIENT_API
INgepIpcClient *
WINAPI
INgepIpcClientGetInstance(
    _In_ CONST wchar_t* szSrc,
    _In_ CONST int nSrcSize
);

#define INgepIpcClientReleaseInstance NGEP_35BA961E

extern "C"
NGEPIPCCLIENT_API
VOID
WINAPI
INgepIpcClientReleaseInstance(
    _In_ CONST INgepIpcClient * pInstance
);

#ifdef NGEPIPCCLIENT_NO_USE_LIB
#pragma warning(push)
#pragma warning(disable : 4505)
typedef INgepIpcClient* (WINAPI *P_INgepIpcClientGetInstance)(CONST wchar_t* szSrc, CONST int nSrcSize);
static INgepIpcClient* GetNgepIpcClientInstance(CONST std::wstring& wstrSrc , CONST std::wstring& strDllPath
    ,bool bLoadDepends = false)
{
    UNREFERENCED_PARAMETER(bLoadDepends);

    HMODULE hModule = LoadLibrary(strDllPath.c_str());
    if (hModule)
    {
        P_INgepIpcClientGetInstance pLoad = (P_INgepIpcClientGetInstance)GetProcAddress(hModule, "NGEP_F2991C0F");   
        if (pLoad)
            return pLoad(wstrSrc.c_str(),(int)wstrSrc.length());
        else
            WriteLog4cPlusBaseW(ERROR_LEVEL, L"LoadLibrary %s af GetProcAddress FsGetInstance is null", strDllPath.c_str());
    }
    else
        WriteLog4cPlusBaseW(ERROR_LEVEL, L"LoadLibrary %s Failed %d", strDllPath.c_str(), GetLastError());
    return nullptr;
}
#pragma warning(pop)
#endif /* NGEPIPCCLIENT_NO_USE_LIB */
#endif /* __INgepIpcClient_INTERFACE_DEFINED__ */
