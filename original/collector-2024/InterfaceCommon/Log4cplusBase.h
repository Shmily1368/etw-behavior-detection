#ifndef LOG4CPLUSBASE_H
#define LOG4CPLUSBASE_H

//使用third目录下新库文件
#define USE_LOG4CPLUS_THIRDPART
//使用静态库
//#define LOG4CPLUSBASE_LOG4CPLUS_STATIC_USE

#include <Windows.h>
#include <Shlwapi.h>
#pragma warning (push)
#pragma warning (disable : 4091)
#include <Shlobj.h>
#pragma warning (pop)
#include <psapi.h>
#pragma comment(lib, "Psapi.lib")
#pragma comment(lib, "Shlwapi.lib")
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
#ifdef LOG4CPLUSBASE_LOG4CPLUS_STATIC_USE
#ifdef _DEBUG
#ifndef _WIN64
#pragma comment(lib,"lib\\Debug\\win32\\log4cplusSUD.lib")
#else
#pragma comment(lib,"lib\\Debug\\x64\\log4cplusSUD.lib")
#endif // WIN32
#else
#ifndef _WIN64
#pragma comment(lib,"lib\\Release\\win32\\log4cplusSU.lib")
#else
#pragma comment(lib,"lib\\Release\\x64\\log4cplusSU.lib")
#endif // WIN32
#endif
#else // !LOG4CPLUSBASE_LOG4CPLUS_STATIC_USE
#ifdef _DEBUG
#ifndef _WIN64
#pragma comment(lib,"bin\\Debug\\win32\\log4cplusUD.lib")
#else
#pragma comment(lib,"bin\\Debug\\x64\\log4cplusUD.lib")
#endif // WIN32
#else
#ifndef _WIN64
#pragma comment(lib,"bin\\Release\\win32\\log4cplusU.lib")
#else
#pragma comment(lib,"bin\\Release\\x64\\log4cplusU.lib")
#endif // WIN32
#endif
#endif // LOG4CPLUSBASE_LOG4CPLUS_STATIC_USE


#include <log4cplus/logger.h>
#include <log4cplus/configurator.h>
#include <log4cplus/layout.h>
#include <log4cplus/loggingmacros.h>
#include <log4cplus/helpers/stringhelper.h>
using namespace log4cplus;
using namespace log4cplus::helpers;

// 定义日志级别，封装log4plus
// 日志级别按顺序，从上到下，依次递增
#define TRACE_LEVEL log4cplus::TRACE_LOG_LEVEL
#define DEBUG_LEVEL log4cplus::DEBUG_LOG_LEVEL //十分频繁的调试信息
#define INFO_LEVEL log4cplus::INFO_LOG_LEVEL //调试信息
#define WARN_LEVEL log4cplus::WARN_LOG_LEVEL //可能失败的情况
#define ERROR_LEVEL log4cplus::ERROR_LOG_LEVEL //意料之外的错误
#define FATAL_LEVEL log4cplus::FATAL_LOG_LEVEL

#define Log4cplusBaseLevel log4cplus::LogLevel

#else
#define TRACE_LEVEL 0
#define DEBUG_LEVEL 1 //十分频繁的调试信息
#define INFO_LEVEL 2 //调试信息
#define WARN_LEVEL 3 //可能失败的情况
#define ERROR_LEVEL 4 //意料之外的错误
#define FATAL_LEVEL 5
#define Log4cplusBaseLevel int

#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE

#include "PykMgr.h"
#include "StringHelp.h"
using namespace std;
#include <strsafe.h>

#define LOG_BUFF_SIZE 8192

class CLog4cplusBase
{
public:
    //CLog4cplusBase() = delete;
    CLog4cplusBase(LPCTSTR lpLogConfigProper
        , LPCTSTR lpInstanceName)
    {
        //StringHelp::OutputDebugStringFormatW(L"CLog4cplusBase this: %u", this);
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
        log4cplus::initialize();
        log4cplus::PropertyConfigurator::doConfigure(lpLogConfigProper);
        m_logger = Logger::getInstance(lpInstanceName);
#else
        UNREFERENCED_PARAMETER(lpLogConfigProper);
        UNREFERENCED_PARAMETER(lpInstanceName);
#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE
    }

    ~CLog4cplusBase()
    {
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
        log4cplus::Logger::shutdown();
#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE
    }

    static void WriteLogPlusW(CLog4cplusBase* pLog, Log4cplusBaseLevel nLevel
        , const CHAR* pszFunction, const CHAR* pszFile, INT nLine
        , const WCHAR* szFormat, ...)
    {
        std::wstring strInfo;
        va_list argptr;
        va_start(argptr, szFormat);
        int len = _vscwprintf(szFormat, argptr);
        strInfo.resize(len + 1, L'\0');
        _vswprintf_s_l(&strInfo[0], len + 1, szFormat
            , NULL, argptr);
        va_end(argptr);
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
        if (pLog == nullptr || !pLog->GetLogger()->getAdditivity())
            OutputDebugStringW(strInfo.c_str());
        else
        {
            if (!strInfo.empty())
            {
                if (pLog->GetLogger()->isEnabledFor(nLevel))
                {
                    std::string strT(CPykMgrTemplate<CP_ACP>(const_cast<const wchar_t*>(strInfo.c_str())));
                    if (!strT.empty())
                    {
                        log4cplus::tostringstream buf;
                        buf << strT.c_str();
                        CHAR chTemp[LOG_BUFF_SIZE] = { 0 };
                        sprintf_s(chTemp, _countof(chTemp), "[%s]%s", pszFunction, pszFile);
                        pLog->GetLogger()->forcedLog(nLevel, buf.str(), chTemp, nLine);
                    }
                }
            }
        }
#else
        UNREFERENCED_PARAMETER(pLog);
        UNREFERENCED_PARAMETER(nLevel);
        UNREFERENCED_PARAMETER(pszFunction);
        UNREFERENCED_PARAMETER(pszFile);
        UNREFERENCED_PARAMETER(nLine);

        OutputDebugStringW(strInfo.c_str());
#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE
    }
    /*void WriteLogPlusW(Log4cplusBaseLevel nLevel
    , const CHAR* pszFunction, const CHAR* pszFile, INT nLine
    , const WCHAR* szFormat, ...)
    {
    WCHAR wzInfo[LOG_BUFF_SIZE] = { 0 };
    va_list argptr;
    va_start(argptr, szFormat);
    _vswprintf_s_l(wzInfo, LOG_BUFF_SIZE, szFormat
    , NULL, argptr);
    va_end(argptr);

    WriteLogPlusW(this, nLevel, pszFunction, pszFile, nLine, wzInfo);
    }*/
    static void WriteLogPlusA(CLog4cplusBase* pLog, Log4cplusBaseLevel nLevel, const CHAR* pszFunction, const CHAR* pszFile, INT nLine
        , const CHAR* szFormat, ...)
    {
        std::string strInfo;
        va_list argptr;
        va_start(argptr, szFormat);
        int len = _vscprintf(szFormat, argptr);
        strInfo.resize(len + 1, L'\0');
        _vsprintf_s_l(&strInfo[0], len + 1, szFormat
            , NULL, argptr);
        va_end(argptr);
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
        if (pLog == nullptr || !pLog->GetLogger()->getAdditivity())
            OutputDebugStringA(strInfo.c_str());
        else
        {
            if (!strInfo.empty())
            {
                if (pLog->GetLogger()->isEnabledFor(nLevel))
                {
                    log4cplus::tostringstream buf;
                    buf << strInfo.c_str();
                    CHAR chTemp[LOG_BUFF_SIZE] = { 0 };
                    sprintf_s(chTemp, _countof(chTemp), "[%s]%s", pszFunction, pszFile);
                    pLog->GetLogger()->forcedLog(nLevel, buf.str(), chTemp, nLine);
                }
            }
        }
#else
        UNREFERENCED_PARAMETER(pLog);
        UNREFERENCED_PARAMETER(nLevel);
        UNREFERENCED_PARAMETER(pszFunction);
        UNREFERENCED_PARAMETER(pszFile);
        UNREFERENCED_PARAMETER(nLine);

        OutputDebugStringA(strInfo.c_str());
#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE
    }
    /*void WriteLogPlusA(Log4cplusBaseLevel nLevel, const CHAR* pszFunction, const CHAR* pszFile, INT nLine
    , const CHAR* szFormat, ...)
    {
    CHAR wzInfo[LOG_BUFF_SIZE] = { 0 };
    va_list argptr;
    va_start(argptr, szFormat);
    _vsprintf_s_l(wzInfo, LOG_BUFF_SIZE, szFormat, NULL, argptr);
    va_end(argptr);

    WriteLogPlusA(this, nLevel, pszFunction, pszFile, nLine, wzInfo);
    }*/
#ifndef LOG4CPLUSBASE_NO_LOG4CPLUS_USE
    Logger* GetLogger()
    {
        return &m_logger;
    }

private:
    Logger m_logger;
#endif // !LOG4CPLUSBASE_NO_LOG4CPLUS_USE
};

//该全局变量在Log4cplusBase.cpp中定义，如通过MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S宏使用lib连接可以不包含该cpp，其他使用方式则需包含cpp或手动定义
extern CLog4cplusBase* g_pLog4cplusBase;
#define WriteLog4cPlusBaseW(Level, logMsg, ...) \
CLog4cplusBase::WriteLogPlusW(g_pLog4cplusBase,Level \
, __FUNCTION__, __FILE__, __LINE__, logMsg, __VA_ARGS__)
#define WriteLog4cPlusBaseA(Level, logMsg, ...) \
CLog4cplusBase::WriteLogPlusA(g_pLog4cplusBase,Level \
, __FUNCTION__, __FILE__, __LINE__, logMsg, __VA_ARGS__)

#define LogInit(LogConfigProper, InstanceName)\
if(g_pLog4cplusBase == nullptr) g_pLog4cplusBase = new CLog4cplusBase(LogConfigProper, InstanceName);

//inline void InitLogSimple(HMODULE hModule)
//{
//    TCHAR szLogConfigProper[1024] = { 0 };
//    GetWindowsDirectory(szLogConfigProper, _countof(szLogConfigProper));
//    szLogConfigProper[3] = L'\0';
//    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L"Program Files");
//
//    SYSTEM_INFO systemInfo = { 0 };
//    GetNativeSystemInfo(&systemInfo);
//
//    if (PROCESSOR_ARCHITECTURE_IA64 == systemInfo.wProcessorArchitecture
//        || PROCESSOR_ARCHITECTURE_ALPHA64 == systemInfo.wProcessorArchitecture
//        || PROCESSOR_ARCHITECTURE_AMD64 == systemInfo.wProcessorArchitecture)
//        wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L" (x86)");
//
//    WCHAR wchTemp[260] = { 0 };
//    GetModuleBaseName(GetCurrentProcess(), NULL, wchTemp, _countof(wchTemp));
//    PathRemoveExtension(wchTemp);
//
//    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L"\\Ngep\\data\\");
//    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), wchTemp);
//    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L".prop");
//
//    GetModuleBaseName(GetCurrentProcess(), hModule, wchTemp, _countof(wchTemp));
//    PathRemoveExtension(wchTemp);
//    std::wstring wstrInstanceName = L"Magic.";
//    wstrInstanceName += wchTemp;
//
//    LogInit(szLogConfigProper
//        , wstrInstanceName.c_str());
//}

inline void InitLogSimple(HMODULE hModule, LPCTSTR lpDir = nullptr)
{
    TCHAR szLogConfigProper[1024] = { 0 };
    if (lpDir)
    {
        _tcscpy_s(szLogConfigProper, lpDir);
        _tcscat_s(szLogConfigProper, L"\\");
    }
    else
    {
        GetWindowsDirectory(szLogConfigProper, _countof(szLogConfigProper));
        szLogConfigProper[3] = L'\0';
        wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L"Program Files");

        SYSTEM_INFO systemInfo = { 0 };
        GetNativeSystemInfo(&systemInfo);

        if (PROCESSOR_ARCHITECTURE_IA64 == systemInfo.wProcessorArchitecture
            || PROCESSOR_ARCHITECTURE_ALPHA64 == systemInfo.wProcessorArchitecture
            || PROCESSOR_ARCHITECTURE_AMD64 == systemInfo.wProcessorArchitecture)
            wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L" (x86)");
        wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L"\\Ngep\\data\\");
    }

    WCHAR wchTemp[260] = { 0 };
    GetModuleBaseName(GetCurrentProcess(), NULL, wchTemp, _countof(wchTemp));
    PathRemoveExtension(wchTemp);
    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), wchTemp);
    wcscat_s(szLogConfigProper, _countof(szLogConfigProper), L".prop");

    GetModuleBaseName(GetCurrentProcess(), hModule, wchTemp, _countof(wchTemp));
    PathRemoveExtension(wchTemp);
    std::wstring wstrInstanceName = L"Magic.";
    wstrInstanceName += wchTemp;

    LogInit(szLogConfigProper
        , wstrInstanceName.c_str());
}
#endif // !LOG4CPLUSBASE_H
