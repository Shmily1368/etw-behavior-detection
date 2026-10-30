#pragma once

#include "MSError.h"
#include "MSGlobalVariable.h"
#include <tchar.h>
//#include <atlbase.h>
#define LEN_BUFFER_SIZE_SERVICE 1024

class CMSReg 
{
public:
    static BOOL
        ReadReg(
            HKEY MainKey
            , LPCTSTR Subkey
            , LPCTSTR Vname
            , std::wstring& strData)
    {
        BOOL bResult = FALSE;
        HKEY hKey;
        WCHAR wzKeyRead[LEN_BUFFER_SIZE_SERVICE] = { 0 };
        DWORD dwSize = LEN_BUFFER_SIZE_SERVICE;
        LSTATUS dwRet = -1;
        dwRet = RegOpenKey(MainKey, Subkey, &hKey);
        if (dwRet == ERROR_SUCCESS)
        {
            if (RegQueryValueEx(hKey, Vname, NULL, NULL, (LPBYTE)wzKeyRead, &dwSize) == ERROR_SUCCESS)
            {
                strData = wzKeyRead;
                bResult = TRUE;
            }
            RegCloseKey(hKey);
        }
        return bResult;
    }

    //写注册表的指定键的数据( Mode:0-新建键数据 1-设置键数据 2-删除指定键 3-删除指定键项 )
    static int 
        DoRegExS(HKEY MainKey
        , LPCTSTR SubKey
        , LPCTSTR Vname
        , DWORD Type
        , WCHAR* szData
        , DWORD dwData
        , int Mode)
    {
        HKEY hKey = NULL;
        DWORD dwDisposition;
        int iResult = 0;

        __try
        {
            switch (Mode)
            {
            case 0:
                if (RegCreateKeyEx(MainKey, SubKey, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_ALL_ACCESS, NULL, &hKey, &dwDisposition) != ERROR_SUCCESS)
                    __leave;
            case 1:
                if (RegOpenKeyEx(MainKey, SubKey, 0, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
                    __leave;
                switch (Type)
                {
                case REG_SZ:
                case REG_EXPAND_SZ:
                    if (RegSetValueEx(hKey, Vname, 0, Type, (LPBYTE)szData, ((DWORD)wcslen(szData) + 1) * 2) == ERROR_SUCCESS)
                        iResult = 1;
                    break;
                case REG_DWORD:
                    if (RegSetValueEx(hKey, Vname, 0, Type, (LPBYTE)&dwData, sizeof(DWORD)) == ERROR_SUCCESS)
                        iResult = 1;
                    break;
                case REG_BINARY:
                    break;
                }
                break;
            case 2:
                if (RegOpenKeyEx(MainKey, SubKey, NULL, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
                    __leave;
                if (RegDeleteKey(hKey, Vname) == ERROR_SUCCESS)
                    iResult = 1;
                break;
            case 3:
                if (RegOpenKeyEx(MainKey, SubKey, NULL, KEY_READ | KEY_WRITE, &hKey) != ERROR_SUCCESS)
                    __leave;
                if (RegDeleteValue(hKey, Vname) == ERROR_SUCCESS)
                    iResult = 1;
                break;
            }
        }
        __finally
        {
            RegCloseKey(MainKey);
            RegCloseKey(hKey);
        }
        return iResult;
    }

    static int 
        DoRegEx(HKEY MainKey
            , LPCTSTR SubKey
            , LPCTSTR Vname
            , DWORD Type
            , WCHAR* szData
            , DWORD dwData
            , int Mode)
    {
        return DoRegExS(MainKey, SubKey, Vname, Type, szData, dwData, Mode);
    }

    static BOOL
        ReadReg(HKEY MainKey
            , LPCTSTR Subkey
            , LPCTSTR Vname
            , LPTSTR szData
            , UINT nDataLength)
    {
        std::wstring strData;
        if (ReadReg(MainKey, Subkey, Vname, strData))
        {
            if (nDataLength > strData.length())
            {
                _tcscpy_s(szData, nDataLength, strData.c_str());
                return TRUE;
            }
        }
        return FALSE;
    }
#ifdef __ATLBASE_H__
    static DWORD
        QueryDWORDValue(
            _Inout_ BOOL& bRet,
            _In_ CONST HKEY hKeyParent,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST std::wstring& wstrValueName
        ) 
    {
        DWORD dwRet = 0;

        ATL::CRegKey RegKey;
        LONG lResult = ERROR_SUCCESS;

        bRet = TRUE;
        do
        {
            lResult = RegKey.Open(
                hKeyParent,
                wstrKeyName.c_str(),
                KEY_READ
            );
            if (ERROR_SUCCESS != lResult)
            {
                bRet = FALSE;
                break;
            }

            lResult = RegKey.QueryDWORDValue(
                wstrValueName.c_str(),
                dwRet
            );
            if (ERROR_SUCCESS != lResult)
            {
                bRet = FALSE;
                break;
            }
        } while (FALSE);

        RegKey.Close();
        return dwRet;
    }

    static MS_ERROR
        SetDWORDValue(
            _In_ CONST HKEY hKeyParent,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST std::wstring& wstrValueName,
            _In_ CONST DWORD dwValue
        ) 
    {
        MS_ERROR MsError = MS_ERROR_DEFAULT;

        ATL::CRegKey RegKey;
        LONG lResult = ERROR_SUCCESS;


        do
        {
            lResult = RegKey.Create(
                hKeyParent,
                wstrKeyName.c_str()
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            lResult = RegKey.SetDWORDValue(
                wstrValueName.c_str(),
                dwValue
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            MsError = MS_ERROR_SUCCESS;
        } while (FALSE);

        RegKey.Close();

        return MsError;
    }


    static std::wstring
        QuerySingleStringValue(
            _In_ CONST HKEY hKeyParent,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST std::wstring& wstrValueName
        ) 
    {
        std::wstring wstrRet;

        ATL::CRegKey RegKey;
        LONG lResult = ERROR_SUCCESS;
        WCHAR wchData[MS_MAX_STRING_LENGTH] = { 0 };
        ULONG ulSizeCh = 0;


        do
        {
            lResult = RegKey.Open(
                hKeyParent,
                wstrKeyName.c_str(),
                KEY_READ
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            ulSizeCh = _countof(wchData);

            lResult = RegKey.QueryStringValue(
                wstrValueName.c_str(),
                wchData,
                &ulSizeCh
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            if (0 == ulSizeCh)
            {
                break;
            }

            wstrRet = wchData;
        } while (FALSE);

        RegKey.Close();

        return wstrRet;
    }

    static MS_ERROR
        SetSingleStringValue(
            _In_ CONST HKEY hKeyParent,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST std::wstring& wstrValueName,
            _In_ CONST std::wstring& wstrValue
        ) 
    {
        MS_ERROR MsError = MS_ERROR_DEFAULT;

        ATL::CRegKey RegKey;
        LONG lResult = ERROR_SUCCESS;
        WCHAR wchData[MS_MAX_STRING_LENGTH] = { 0 };
        ULONG ulSizeCh = 0;


        do
        {
            lResult = RegKey.Create(
                hKeyParent,
                wstrKeyName.c_str()
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            ulSizeCh = _countof(wchData);

            lResult = RegKey.SetStringValue(
                wstrValueName.c_str(),
                wstrValue.c_str()
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            MsError = MS_ERROR_SUCCESS;
        } while (FALSE);

        RegKey.Close();

        return MsError;
    }

    static VOID
        DeleteValue(
            _In_ CONST HKEY hKeyParent,
            _In_ CONST std::wstring& wstrKeyName,
            _In_ CONST std::wstring& wstrValueName
        ) 
    {
        ATL::CRegKey RegKey;
        LONG lResult = ERROR_SUCCESS;
        WCHAR wchData[MS_MAX_STRING_LENGTH] = { 0 };
        ULONG ulSizeCh = 0;


        do
        {
            lResult = RegKey.Open(
                hKeyParent,
                wstrKeyName.c_str(),
                KEY_WRITE
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }

            ulSizeCh = _countof(wchData);

            lResult = RegKey.DeleteValue(
                wstrValueName.c_str()
            );
            if (ERROR_SUCCESS != lResult)
            {
                break;
            }
        } while (FALSE);

        RegKey.Close();

        return;
    }
#endif // __ATLBASE_H__

private:
    CMSReg() {}

    ~CMSReg() {}
};
