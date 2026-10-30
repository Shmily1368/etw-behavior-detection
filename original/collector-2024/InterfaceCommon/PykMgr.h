#pragma once
#ifdef __cpp_variadic_templates
#if __cpp_variadic_templates >= 200704L
#define __CPP11Plus__
#endif
#endif
#include <windows.h>
#include <assert.h>
template <UINT nCodePage = 936>
class CPykMgrTemplate
{
public:
    CPykMgrTemplate() : m_pcData(NULL), m_pwcData(NULL) {}
    CPykMgrTemplate(const char* pStr) : m_pcData(NULL), m_pwcData(NULL)
    {
        if (pStr)
        {
            m_pcData = new char[strlen(pStr) + 1];
            strcpy_s(m_pcData, strlen(pStr) + 1, pStr);
        }
    }
    CPykMgrTemplate(const wchar_t* pStr) : m_pcData(NULL), m_pwcData(NULL)
    {
        if (pStr)
        {
            m_pwcData = new wchar_t[wcslen(pStr) + 1];
            wcscpy_s(m_pwcData, wcslen(pStr) + 1, pStr);
        }
    }

    CPykMgrTemplate(const char* pStr, const char* pEnd) : m_pcData(NULL), m_pwcData(NULL)
    {
        if (pStr && pEnd)
        {
            m_pcData = new char[pEnd - pStr + 1];
            strncpy_s(m_pcData, pEnd - pStr + 1, pStr, pEnd - pStr);
        }
    }
    CPykMgrTemplate(const wchar_t* pStr, const wchar_t* pEnd) : m_pcData(NULL), m_pwcData(NULL)
    {
        if (pStr)
        {
            m_pwcData = new wchar_t[pEnd - pStr + 1];
            wcsncpy_s(m_pwcData, pEnd - pStr + 1, pStr, pEnd - pStr);
        }
    }
#ifdef __CPP11Plus__
    CPykMgrTemplate(const CPykMgrTemplate&) = delete;
#endif // __CPP11Plus__

    operator const char* ()
    {
        if (!m_pcData && m_pwcData)
        {
            int nLen = WideCharToMultiByte(nCodePage, 0, m_pwcData, -1, NULL, 0, NULL, NULL);
            if (0 != nLen)
            {
                m_pcData = new char[nLen + 1];
                WideCharToMultiByte(nCodePage, 0, m_pwcData, -1, m_pcData, nLen + 1, NULL, NULL);
            }
        }
        else
        {
            if (NULL != m_pcData && NULL == m_pwcData)
            {
                assert(FALSE);
            }
        }
        return m_pcData;
    }

    operator const wchar_t* ()
    {
        if (!m_pwcData && m_pcData)
        {
            int nLen = MultiByteToWideChar(nCodePage, 0, m_pcData, -1, NULL, 0);
            if (0 != nLen)
            {
                m_pwcData = new wchar_t[nLen + 1];
                MultiByteToWideChar(nCodePage, 0, m_pcData, -1, m_pwcData, nLen + 1);
            }
        }
        else
        {
            if (NULL != m_pwcData && NULL == m_pcData)
            {
                assert(FALSE);
            }
        }
        return m_pwcData;
    }

    void Reset()
    {
        if (m_pcData)
        {
            delete[]m_pcData;
            m_pcData = NULL;
        }
        if (m_pwcData)
        {
            delete[]m_pwcData;
            m_pwcData = NULL;
        }
    }

    CPykMgrTemplate& Reset(const char* pStr)
    {
        Reset();
        if (pStr)
        {
            m_pcData = new char[strlen(pStr) + 1];
            strcpy_s(m_pcData, strlen(pStr) + 1, pStr);
        }
        return *this;
    }

    CPykMgrTemplate& Reset(const wchar_t* pStr)
    {
        Reset();
        if (pStr)
        {
            m_pwcData = new wchar_t[wcslen(pStr) + 1];
            wcscpy_s(m_pwcData, wcslen(pStr) + 1, pStr);
        }
        return *this;
    }

    CPykMgrTemplate& Reset(const char* pStr, const char* pEnd)
    {
        Reset();
        if (pStr && pEnd)
        {
            m_pcData = new char[pEnd - pStr + 1];
            strncpy_s(m_pcData, pEnd - pStr + 1, pStr, pEnd - pStr);
        }
        return *this;
    }
    CPykMgrTemplate& Reset(const wchar_t* pStr, const wchar_t* pEnd)
    {
        Reset();
        if (pStr)
        {
            m_pwcData = new wchar_t[pEnd - pStr + 1];
            wcsncpy_s(m_pwcData, pEnd - pStr + 1, pStr, pEnd - pStr);
        }
        return *this;
    }

    ~CPykMgrTemplate()
    {
        Reset();
    }
private:
    char* m_pcData;
    wchar_t* m_pwcData;
};

template <UINT nCodePage = 936>
class CPykMgrTemplate_Null2Empty :public CPykMgrTemplate<nCodePage>
{
public:
    CPykMgrTemplate_Null2Empty() :CPykMgrTemplate<nCodePage>()
    {}
    CPykMgrTemplate_Null2Empty(const wchar_t* pStr) :CPykMgrTemplate<nCodePage>(pStr)
    {}
    CPykMgrTemplate_Null2Empty(const char* pStr) :CPykMgrTemplate<nCodePage>(pStr)
    {}
    operator const char* ()
    {
        const char* pRet = CPykMgrTemplate::operator const char* ();
        return pRet == nullptr ? "" : pRet;
    }
    operator const wchar_t* ()
    {
        const wchar_t* pRet = CPykMgrTemplate::operator const wchar_t* ();
        return pRet == nullptr ? "" : pRet;
    }

private:

};
#define CPykMgrTemplate_N2E CPykMgrTemplate_Null2Empty
#ifdef __CPP11Plus__
using CPykMgr = CPykMgrTemplate<>;
#endif // __CPP11Plus__