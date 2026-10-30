#pragma once
#include "MSGlobalVariable.h"
#include "PykMgr.h"

typedef struct _Sample_Info
{
	char szUUIDA[64] = { 0 };
	char szEventTimeA[100] = { 0 };
	char  szFileNameA[MS_MAX_NAME] = { 0 };
	char  szFilePathA[MS_MAX_PATH] = { 0 };
	char  szMD5A[100] = { 0 };
	char  szLogIDA[100] = { 0 };
	char  szLogNameA[100] = { 0 };
	char  szUserA[MS_MAX_PATH] = { 0 };
	char  szSizeA[20] = { 0 };

	char szUUIDUtf8[64] = { 0 };
	char szEventTimeUtf8[100] = { 0 };
	char  szFileNameUtf8[MS_MAX_NAME] = { 0 };
	char  szFilePathUtf8[MS_MAX_PATH] = { 0 };
	char  szMD5Utf8[100] = { 0 };
	char  szLogIDUtf8[100] = { 0 };
	char  szLogNameUtf8[100] = { 0 };
	char  szUserUtf8[MS_MAX_PATH] = { 0 };
	char  szSizeUtf8[20] = { 0 };

	wchar_t szUUIDW[64] = { 0 };
	wchar_t szEventTimeW[100] = { 0 };
	wchar_t  szFileNameW[MS_MAX_NAME] = { 0 };
	wchar_t  szFilePathW[MS_MAX_PATH] = { 0 };
	wchar_t  szMD5W[100] = { 0 };
	wchar_t  szLogIDW[100] = { 0 };
	wchar_t  szLogNameW[100] = { 0 };
	wchar_t  szUserW[MS_MAX_PATH] = { 0 };
	wchar_t  szSizeW[20] = { 0 };

	void SetUUID(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szUUIDW, _countof(szUUIDW)
			, (char*)&szUUIDA, _countof(szUUIDA)
			, (char*)&szUUIDUtf8, _countof(szUUIDUtf8));
	}
	void SetUUID(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szUUIDW, _countof(szUUIDW)
			, (char*)&szUUIDA, _countof(szUUIDA)
			, (char*)&szUUIDUtf8, _countof(szUUIDUtf8));
	}
	void SetUUID_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szUUIDW, _countof(szUUIDW)
			, (char*)&szUUIDA, _countof(szUUIDA)
			, (char*)&szUUIDUtf8, _countof(szUUIDUtf8));
	}

	void SetEventTime(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szEventTimeW, _countof(szEventTimeW)
			, (char*)&szEventTimeA, _countof(szEventTimeA)
			, (char*)&szEventTimeUtf8, _countof(szEventTimeUtf8));
	}
	void SetEventTime(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szEventTimeW, _countof(szEventTimeW)
			, (char*)&szEventTimeA, _countof(szEventTimeA)
			, (char*)&szEventTimeUtf8, _countof(szEventTimeUtf8));
	}
	void SetEventTime_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szEventTimeW, _countof(szEventTimeW)
			, (char*)&szEventTimeA, _countof(szEventTimeA)
			, (char*)&szEventTimeUtf8, _countof(szEventTimeUtf8));
	}

	void SetFileName(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szFileNameW, _countof(szFileNameW)
			, (char*)&szFileNameA, _countof(szFileNameA)
			, (char*)&szFileNameUtf8, _countof(szFileNameUtf8));
	}
	void SetFileName(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szFileNameW, _countof(szFileNameW)
			, (char*)&szFileNameA, _countof(szFileNameA)
			, (char*)&szFileNameUtf8, _countof(szFileNameUtf8));
	}
	void SetFileName_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szFileNameW, _countof(szFileNameW)
			, (char*)&szFileNameA, _countof(szFileNameA)
			, (char*)&szFileNameUtf8, _countof(szFileNameUtf8));
	}

	void SetFilePath(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szFilePathW, _countof(szFilePathW)
			, (char*)&szFilePathA, _countof(szFilePathA)
			, (char*)&szFilePathUtf8, _countof(szFilePathUtf8));
	}
	void SetFilePath(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szFilePathW, _countof(szFilePathW)
			, (char*)&szFilePathA, _countof(szFilePathA)
			, (char*)&szFilePathUtf8, _countof(szFilePathUtf8));
	}
	void SetFilePath_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szFilePathW, _countof(szFilePathW)
			, (char*)&szFilePathA, _countof(szFilePathA)
			, (char*)&szFilePathUtf8, _countof(szFilePathUtf8));
	}

	void SetMd5(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szMD5W, _countof(szMD5W)
			, (char*)&szMD5A, _countof(szMD5A)
			, (char*)&szMD5Utf8, _countof(szMD5Utf8));
	}
	void SetMd5(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szMD5W, _countof(szMD5W)
			, (char*)&szMD5A, _countof(szMD5A)
			, (char*)&szMD5Utf8, _countof(szMD5Utf8));
	}
	void SetMd5_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szMD5W, _countof(szMD5W)
			, (char*)&szMD5A, _countof(szMD5A)
			, (char*)&szMD5Utf8, _countof(szMD5Utf8));
	}

	void SetLogId(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szLogIDW, _countof(szLogIDW)
			, (char*)&szLogIDA, _countof(szLogIDA)
			, (char*)&szLogIDUtf8, _countof(szLogIDUtf8));
	}
	void SetLogId(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szLogIDW, _countof(szLogIDW)
			, (char*)&szLogIDA, _countof(szLogIDA)
			, (char*)&szLogIDUtf8, _countof(szLogIDUtf8));
	}
	void SetLogId_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szLogIDW, _countof(szLogIDW)
			, (char*)&szLogIDA, _countof(szLogIDA)
			, (char*)&szLogIDUtf8, _countof(szLogIDUtf8));
	}

	void SetLogName(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szLogNameW, _countof(szLogNameW)
			, (char*)&szLogNameA, _countof(szLogNameA)
			, (char*)&szLogNameUtf8, _countof(szLogNameUtf8));
	}
	void SetLogName(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szLogNameW, _countof(szLogNameW)
			, (char*)&szLogNameA, _countof(szLogNameA)
			, (char*)&szLogNameUtf8, _countof(szLogNameUtf8));
	}
	void SetLogName_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szLogNameW, _countof(szLogNameW)
			, (char*)&szLogNameA, _countof(szLogNameA)
			, (char*)&szLogNameUtf8, _countof(szLogNameUtf8));
	}

	void SetUser(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szUserW, _countof(szUserW)
			, (char*)&szUserA, _countof(szUserA)
			, (char*)&szUserUtf8, _countof(szUserUtf8));
	}
	void SetUser(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szUserW, _countof(szUserW)
			, (char*)&szUserA, _countof(szUserA)
			, (char*)&szUserUtf8, _countof(szUserUtf8));
	}
	void SetUser_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szUserW, _countof(szUserW)
			, (char*)&szUserA, _countof(szUserA)
			, (char*)&szUserUtf8, _countof(szUserUtf8));
	}

	void SetSize(const wchar_t* lpIn)
	{
		SetData(lpIn, (wchar_t*)&szSizeW, _countof(szSizeW)
			, (char*)&szSizeA, _countof(szSizeA)
			, (char*)&szSizeUtf8, _countof(szSizeUtf8));
	}
	void SetSize(const char* lpIn)
	{
		SetDataA(lpIn, (wchar_t*)&szSizeW, _countof(szSizeW)
			, (char*)&szSizeA, _countof(szSizeA)
			, (char*)&szSizeUtf8, _countof(szSizeUtf8));
	}
	void SetSize_UTF8(const char* lpIn)
	{
		SetDataUtf8(lpIn, (wchar_t*)&szSizeW, _countof(szSizeW)
			, (char*)&szSizeA, _countof(szSizeA)
			, (char*)&szSizeUtf8, _countof(szSizeUtf8));
	}
private:
	void SetData(const wchar_t* lpIn
		, wchar_t* lpDstW, unsigned long long nSizeDstW
		, char* lpDstA, unsigned long long nSizeDstA
		, char* lpDstUtf8, unsigned long long nSizeDstUtf8)
	{
		_tcscpy_s(lpDstW,(rsize_t)nSizeDstW, lpIn);
		std::string strT = CPykMgrTemplate<CP_ACP>(lpIn);
		strcpy_s(lpDstA, (rsize_t)nSizeDstA, strT.c_str());

		strT = CPykMgrTemplate<CP_UTF8>(lpIn);
		strcpy_s(lpDstUtf8, (rsize_t)nSizeDstUtf8, strT.c_str());
	}
	void SetDataA(const char* lpIn
		, wchar_t* lpDstW, unsigned long long nSizeDstW
		, char* lpDstA, unsigned long long nSizeDstA
		, char* lpDstUtf8, unsigned long long nSizeDstUtf8)
	{
		strcpy_s(lpDstA, (rsize_t)nSizeDstA, lpIn);
		std::wstring strT = CPykMgrTemplate<CP_ACP>(lpIn);
		_tcscpy_s(lpDstW, (rsize_t)nSizeDstW, strT.c_str());

		std::string strTUtf8 = CPykMgrTemplate<CP_UTF8>(strT.c_str());
		strcpy_s(lpDstUtf8, (rsize_t)nSizeDstUtf8, strTUtf8.c_str());
	}

	void SetDataUtf8(const char* lpIn
		, wchar_t* lpDstW, unsigned long long nSizeDstW
		, char* lpDstA, unsigned long long nSizeDstA
		, char* lpDstUtf8, unsigned long long nSizeDstUtf8)
	{
		strcpy_s(lpDstUtf8, (rsize_t)nSizeDstUtf8, lpIn);
		std::wstring strT = CPykMgrTemplate<CP_UTF8>(lpIn);
		_tcscpy_s(lpDstW, (rsize_t)nSizeDstW, strT.c_str());

		std::string strTA = CPykMgrTemplate<CP_ACP>(strT.c_str());
		strcpy_s(lpDstA, (rsize_t)nSizeDstA, strTA.c_str());
	}
}Sample_Info;