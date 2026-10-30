#ifndef LOG4CPLUSBASEDYNAMIC_H
#define LOG4CPLUSBASEDYNAMIC_H
#include "Log4cplusBase.h"
#include "StringHelp.h"
#include "NgepRegMgr.h"
#include <thread>
#include <sddl.h>
#define LOG_EVENT_NAME L"Global\\MSLOG_{0E799127-723D-4B6E-9505-FE2B35B0CE44}"

inline void InitLogSimpleDynamic(HMODULE hModule)
{
    HANDLE hEvent = OpenEvent(NULL, FALSE, LOG_EVENT_NAME);
    if (hEvent == NULL)
    {
        StringHelp::OutputDebugStringFormatW(L"OpenEvent Failed so Create");
        SECURITY_ATTRIBUTES sa;
        sa.nLength = sizeof(sa);
        sa.bInheritHandle = FALSE;

        if (!ConvertStringSecurityDescriptorToSecurityDescriptor(
            L"D:(A;OICI;GA;;;WD)", // 允许所有用户具有完全访问权限
            SDDL_REVISION_1,
            &(sa.lpSecurityDescriptor),
            NULL))
            StringHelp::OutputDebugStringFormatW(L"ConvertStringSecurityDescriptorToSecurityDescriptor Failed Error:%d", GetLastError());
        hEvent = CreateEvent(&sa, TRUE, FALSE, LOG_EVENT_NAME);
        if (hEvent == NULL)
            StringHelp::OutputDebugStringFormatW(L"CreateEvent Failed Error:%d", GetLastError());
    }
    std::wstring strLast;
    do
    {
        ResetEvent(hEvent);
        do
        {
            CNgepRegMgr pRegCfg;
            pRegCfg.LoadReg();
            StringHelp::OutputDebugStringFormatW(L"pRegCfg.LoadReg %s", pRegCfg.m_strDebugCfgDir.c_str());
            if (strLast == pRegCfg.m_strDebugCfgDir
                && g_pLog4cplusBase != nullptr)
                break;
            if (g_pLog4cplusBase != nullptr)
            {
                delete g_pLog4cplusBase;
                g_pLog4cplusBase = nullptr;
            }
            InitLogSimple(hModule, pRegCfg.m_strDebugCfgDir.empty() ? nullptr : pRegCfg.m_strDebugCfgDir.c_str());
            if (strLast != pRegCfg.m_strDebugCfgDir)
                strLast = pRegCfg.m_strDebugCfgDir;
        } while (false);        
        WaitForSingleObject(hEvent, INFINITE);
        StringHelp::OutputDebugStringFormatW(L"WaitForSingleObject af notify");
    } while (true);
}

inline int NotifyLogCfgChanged()
{
    HANDLE hEvent = OpenEvent(SYNCHRONIZE | EVENT_MODIFY_STATE, FALSE, LOG_EVENT_NAME);
    if (hEvent)
        return SetEvent(hEvent);
    else
        return -1;
}

class Log4cplusBaseDynamicInitHelper
{
public:
    static void RunLogSimpleDynamicThread(HMODULE hModule)
    {
        HANDLE hThread = CreateThread(NULL, 0, ThreadLogSimpleDynamic, hModule, 0, NULL);
        if (NULL == hThread)
        {
            StringHelp::OutputDebugStringFormatW(L"CreateThread Failed Error:%d", GetLastError());
        }
        else
        {
            CloseHandle(hThread);
            hThread = NULL;
        }
    }

#pragma warning (push)
#pragma warning (disable : 4702)
    static DWORD WINAPI ThreadLogSimpleDynamic(LPVOID lpParameter)
    {
        InitLogSimpleDynamic((HMODULE)lpParameter);
        return 0;
    }
#pragma warning (pop)
private:

};

#endif // !LOG4CPLUSBASEDYNAMIC_H
