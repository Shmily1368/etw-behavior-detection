#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN // 从 Windows 头文件中排除极少使用的信息
#endif // !WIN32_LEAN_AND_MEAN

// Windows 头文件:
#include <windows.h>
#ifdef MSCOMMON_EXPORTS
#include "..\MSCommon\MSCommonApi.h"
#else
#ifndef MSCOMMONS_EXPORTS
#ifndef MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S
#include "..\MSCommon\MSCommonApi.h"
#endif
#endif
#endif
#include "MSSingleInstance.h"
#include "..\MSCommon\MSBasic.h"
#include "..\MSCommon\MSPath.h"
#include "..\MSCommon\MSDisableFsRedirection.h"

class CMSResource :
#ifdef MSCOMMON_EXPORTS
    public IMSResource,
#else
#ifndef MSCOMMONS_EXPORTS
#ifndef MS_PREPROCESSOR_DEFINITION_USE_MS_COMMON_S
    public IMSResource,
#endif
#endif
#endif
    public CMSSingleInstance<CMSResource>
{
    friend class CMSSingleInstance<CMSResource>;

public:
    std::map<MS_ENUM_RESOURCE_ID, MS_STRUCT_RESOURCE_INFO> m_mapResourceList;

    MS_ERROR
        WINAPI
        Init( );

    MS_ERROR
        WINAPI
        Unload();

    MS_STRUCT_RESOURCE_INFO
        WINAPI
        Get(
        _In_ CONST MS_ENUM_RESOURCE_ID enumResourceId
        );

private:
    CMSResource();

    ~CMSResource();

    VOID
        SetResourceList();
    VOID
        SetResourceInfo_InInstallDir(_MS_ENUM_RESOURCE_ID nId
        , LPCTSTR lpX86PathName
        , LPCTSTR lpX64PathName);
    VOID
        SetResourceInfo(_MS_ENUM_RESOURCE_ID nId
            , MS_ENUM_CLIENT_DIRECTORY_TYPE nDirType
            , LPCTSTR lpX86PathName
            , LPCTSTR lpX64PathName);
};
