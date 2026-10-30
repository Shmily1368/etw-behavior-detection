
#pragma once

#include <Windows.h>

template<class T>
class CMSSingleInstance
{
public:
    static
        T *
        WINAPI
        GetInstance()
    {
        if (NULL == ms_pInstance)
        {
            ms_pInstance = new T;
        }

        return ms_pInstance;
    }

    static
        VOID
        WINAPI
        ReleaseInstance( )
    {
        if (NULL != ms_pInstance)
        {
            delete ms_pInstance;
            ms_pInstance = NULL;
        }

        return;
    }

protected:
    BOOL m_bInitFlag;

    CMSSingleInstance()
    {
        m_bInitFlag = FALSE;
    }

    ~CMSSingleInstance()
    {
        m_bInitFlag = FALSE;
    }

    VOID
        SetInitFlag(
        _In_ CONST BOOL bInitFlag
        )
    {
        m_bInitFlag = bInitFlag;

        return;
    }

    BOOL
        GetInitFlag()
    {
        return m_bInitFlag;
    }

private:
    static T * ms_pInstance;
};

template<class T> T * CMSSingleInstance<T>::ms_pInstance = NULL;
