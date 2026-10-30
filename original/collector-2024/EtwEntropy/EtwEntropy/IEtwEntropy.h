#pragma once
#include <Windows.h>
#include <xstring>
#include <vector>

class ICEtwEntropy
{
public:
    virtual double calculate_entropy(const std::vector<int> counted_bytes, const std::streamsize total_length) = 0;
    virtual double entropy_as_feature(std::vector<std::string> filelist) = 0;
    virtual double ICalcEntropyByFileListA(const char* szIn, const int nInSize) = 0;
    virtual double ICalcEntropyByFileListW(const wchar_t* szIn, const int nInSize) = 0;
    virtual double ICalcEntropyByFileListUtf8(const char* szIn, const int nInSize) = 0;
private:

};

typedef ICEtwEntropy* (*P_EEGetInstance)();

static ICEtwEntropy* GetEtwEntropyInstance(bool bLoadDepends = false)
{
    UNREFERENCED_PARAMETER(bLoadDepends);

    std::wstring strDllPath;
    strDllPath = L"EtwEntropy.dll";
    HMODULE hModule = LoadLibrary(strDllPath.c_str());
    if (hModule)
    {
        P_EEGetInstance pLoad = (P_EEGetInstance)GetProcAddress(hModule, "EEGetInstance");   //FsGetInstance
        if (pLoad)
            return pLoad();
    }
    return nullptr;
}