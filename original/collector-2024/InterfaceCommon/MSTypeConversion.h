#pragma once
#include "PykMgr.h"
#include "MSGlobalVariable.h"
#include <strsafe.h>
#pragma warning(push)
#pragma warning(disable : 4995)
#include <atlenc.h>
#pragma warning(pop)

class CMSTypeConversion 
{
public:

    static std::wstring
        GenGuidRegistryFormat()
    {
        std::wstring wstrRet = L"";

        GUID Guid = { 0 };
        WCHAR wchGuid[MS_MAX_PATH] = { 0 };


        do
        {
            Guid = GenGuidStructFormat();

            StringCchPrintf(wchGuid, _countof(wchGuid), L"{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
                Guid.Data1,
                Guid.Data2,
                Guid.Data3,
                Guid.Data4[0], Guid.Data4[1],
                Guid.Data4[2], Guid.Data4[3], Guid.Data4[4], Guid.Data4[5], Guid.Data4[6], Guid.Data4[7]
            );

            wstrRet = wchGuid;
        } while (FALSE);

        return wstrRet;
    }

    static GUID
        GenGuidStructFormat()

    {
        GUID GuidRet = { 0 };

        HRESULT hResult = S_OK;


        do
        {
            hResult = CoCreateGuid(&GuidRet);
            if (S_OK != hResult)
            {
                break;
            }
        } while (FALSE);

        return GuidRet;
    }


    static std::string
        XorAndBase64String(
            _In_ CONST std::string& strInPut,
            _In_ unsigned char xorKey
        )
    {
        std::string strRet = "";
        LPSTR lpTemp = NULL;

        do
        {
            if (strInPut.empty())
            {
                break;
            }

            strRet = strInPut;
            for (size_t nPos = 0; nPos < strRet.length(); ++nPos)
            {
                strRet[nPos] = strRet[nPos] ^ xorKey;
            }

            int nDstLen = ATL::Base64EncodeGetRequiredLength((int)strRet.length(), ATL_BASE64_FLAG_NOCRLF);
            lpTemp = (LPSTR)calloc(1, nDstLen + 1);
            if (NULL == lpTemp)
            {
                break;
            }

            if (!ATL::Base64Encode((unsigned char*)strRet.c_str(), (int)strRet.length(), lpTemp, &nDstLen, ATL_BASE64_FLAG_NOCRLF))
            {
                break;
            }

            strRet = lpTemp;

        } while (FALSE);

        if (NULL != lpTemp)
        {
            free(lpTemp);
            lpTemp = NULL;
        }

        return strRet;
    }

    static std::string
        DecryptBase64AndXor(
            _In_ CONST std::string& strInPut,
            _In_ unsigned char xorKey
        )
    {
        std::string strRet = "";
        unsigned char* lpTemp = NULL;

        do
        {
            if (strInPut.empty())
            {
                break;
            }

            strRet = strInPut;

            int nDstLen = ATL::Base64DecodeGetRequiredLength((int)strRet.length());
            lpTemp = (unsigned char*)calloc(1, nDstLen + 1);
            if (NULL == lpTemp)
            {
                break;
            }

            if (!ATL::Base64Decode(strRet.c_str(), (int)strRet.length(), lpTemp, &nDstLen))
            {
                break;
            }

            for (int nPos = 0; nPos < nDstLen; ++nPos)
            {
                lpTemp[nPos] = lpTemp[nPos] ^ xorKey;
            }

            strRet = (const char*)lpTemp;

        } while (FALSE);

        if (NULL != lpTemp)
        {
            free(lpTemp);
            lpTemp = NULL;
        }

        return strRet;
    }

private:
    CMSTypeConversion(){}

    ~CMSTypeConversion(){}
};
