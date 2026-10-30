#ifndef STRINGHELP_H_INCLUDED
#define STRINGHELP_H_INCLUDED

#ifdef _WIN32
#include <xstring>
#include <tchar.h>
#include <stdarg.h>
#include <WinBase.h>
#endif // _WIN32

#define MAX_PATH_RE 1024
#define IF_VALUE_HANDLE(h) if(h != NULL && h != INVALID_HANDLE_VALUE)
#define IF_UNVALUE_HANDLE(h) if(h == NULL || h == INVALID_HANDLE_VALUE)

#ifndef WSTD_DEL
#define WSTD_DEL(x) { if ((x)) { delete (x); (x)=NULL; } }
#endif

#ifndef WSTD_DELM
#define WSTD_DELM(x) { if ((x)) { delete[] (x); (x)=NULL; } }
#endif

#ifndef WSTD_CLOSE_HANDLE
#define WSTD_CLOSE_HANDLE(x) {if((x)){	CloseHandle((x)); (x)=NULL;}}
#endif

#ifndef GOOD_HANDLE
#define GOOD_HANDLE(a) (((a)!=INVALID_HANDLE_VALUE) && ((a)!=NULL))
#endif

#ifndef SHOWINFO_BUFSIZE
#define SHOWINFO_BUFSIZE 4096
#endif

#ifdef UNICODE
#ifndef __FILENAMEW__
#define __FILENAMEW__ wcsrchr(__FILEW__,L'\\') ? wcsrchr(__FILEW__,L'\\') + 1 : __FILEW__
#endif
#endif // UNICODE

#ifndef __FILENAME__
#define __FILENAME__ strrchr(__FILE__,'\\') ? strrchr(__FILE__,'\\') + 1 : __FILE__
#endif

#include <stdio.h>
#include <assert.h>
#define OUT_SIZE 40960
namespace StringHelp 
{
#ifdef _WIN32
	inline void OutputDebugStringFormatA(const char* _Format,...)
	{
		
		va_list arglist;
		char szOut[OUT_SIZE] = { 0 };
		va_start(arglist, _Format);
		_vsprintf_s_l(szOut, OUT_SIZE, _Format, NULL, arglist);
		OutputDebugStringA(szOut);
		va_end(arglist);
	}
#ifdef UNICODE
	inline void OutputDebugStringFormatW(const TCHAR* _Format, ...)
	{
		va_list arglist;
		TCHAR szOut[OUT_SIZE] = { 0 };
		va_start(arglist, _Format);
		_vswprintf_s_l(szOut, OUT_SIZE, _Format, NULL, arglist);
		OutputDebugStringW(szOut);
		va_end(arglist);
	}
#endif // UNICODE
#endif// _WIN32

#if _WIN32
	inline void printfFormat(const char* _Format, ...)
	{
		va_list arglist;
		char szOut[OUT_SIZE] = { 0 };
		va_start(arglist, _Format);
		_vsprintf_s_l(szOut, OUT_SIZE, _Format, NULL, arglist);
		printf(szOut);
		va_end(arglist);
	}
#ifdef UNICODE
	inline void _tprintfFormat(const TCHAR* _Format, ...)
	{
		va_list arglist;
		TCHAR szOut[OUT_SIZE] = { 0 };
		va_start(arglist, _Format);
		_vswprintf_s_l(szOut, OUT_SIZE, _Format, NULL, arglist);
		_tprintf(szOut);
		va_end(arglist);
	}
#endif // UNICODE		
#endif

#ifdef _WIN32
	inline void StringFormatA(char* szBuffer,int nBufferSize, _In_z_ _Printf_format_string_ LPCSTR pszFormat, ...)
	{
		va_list argList;
		va_start(argList, pszFormat);
		vsprintf_s(szBuffer, nBufferSize, pszFormat, argList);
		va_end(argList);
	}
#ifdef UNICODE
	inline void StringFormatW(wchar_t* szBuffer,int nBufferSize, _In_z_ _Printf_format_string_ LPCWSTR pszFormat, ...)
	{
		va_list argList;
		va_start(argList, pszFormat);
		vswprintf_s(szBuffer, nBufferSize, pszFormat, argList);
		va_end(argList);
	}
#endif // UNICODE
	//inline void stringMaxPathCheckW(std::wstring& strSrc, std::wstring& strTrg)
	//{
	//	if (strSrc.length() >= MAX_PATH && strSrc.find(L"\\\\?\\") == strSrc.npos)
	//		strTrg = L"\\\\?\\" + strSrc;
	//	else
	//		strTrg = strSrc;
	//}

	//inline void stringMaxPathCheckA(std::string& strSrc, std::string& strTrg)
	//{
	//	if (strSrc.length() >= MAX_PATH && strSrc.find("\\\\?\\") == strSrc.npos)
	//		strTrg = "\\\\?\\" + strSrc;
	//	else
	//		strTrg = strSrc;
	//}

	//inline void NewGUIDA(std::string& strGuid)
	//{
	//	GUID guid;
	//	CoCreateGuid(&guid);
	//	char chGUID[64] = { 0 };
	//	sprintf_s(chGUID, 64, "%08X%04X%04X%02X%02X"
	//		, guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1]);
	//	strGuid = chGUID;
	//}
#ifdef UNICODE

	//inline void NewGUIDW(std::wstring& strGuid)
	//{
	//	GUID guid;
	//	CoCreateGuid(&guid);
	//	wchar_t chGUID[64] = { 0 };
	//	swprintf_s(chGUID, 64, L"%08X%04X%04X%02X%02X"
	//		, guid.Data1, guid.Data2, guid.Data3, guid.Data4[0], guid.Data4[1]);
	//	strGuid = chGUID;
	//}
#endif // UNICODE
#endif

#ifdef _WIN32
	namespace help {
		inline void get_nextval(const char* T, int next[])
		{
			int j = 0, k = -1;
			next[0] = -1;
			while (T[j] != '\0')
			{
				if (k == -1 || T[j] == T[k])
				{
					++j; ++k;
					if (T[j] != T[k])
						next[j] = k;
					else
						next[j] = next[k];
				}
				else
					k = next[k];
			}
		}
#ifdef UNICODE
		inline void get_nextval(const WCHAR* T, int next[])
		{
			int j = 0, k = -1;
			next[0] = -1;
			while (T[j] != '\0')
			{
				if (k == -1 || T[j] == T[k])
				{
					++j; ++k;
					if (T[j] != T[k])
						next[j] = k;
					else
						next[j] = next[k];
				}
				else
					k = next[k];
			}
		}
#endif // UNICODE
	}

	inline int match(const char* Text, const char* Pattern)
	{
		if (!Text || !Pattern || Pattern[0] == '\0' || Text[0] == '\0')//
			return -1;
		int len = 0;
		const char* c = Pattern;
		while (*c++ != '\0')
			++len;
		int* next = new int[len + 1];
		help::get_nextval(Pattern, next);

		int index = 0, i = 0, j = 0;
		while (Text[i] != '\0' && Pattern[j] != '\0')
		{
			if (Text[i] == Pattern[j])
			{
				++i;
				++j;
			}
			else
			{
				index += j - next[j];
				if (next[j] != -1)
					j = next[j];
				else
				{
					j = 0;
					++i;
				}
			}
		}

		delete[]next;
		if (Pattern[j] == '\0')
			return index;
		else
			return -1;
	}
#ifdef UNICODE

	inline int match(const WCHAR* Text, const WCHAR* Pattern)
	{
		if (!Text || !Pattern || Pattern[0] == '\0' || Text[0] == '\0')//
			return -1;
		int len = 0;
		const WCHAR* c = Pattern;
		while (*c++ != '\0')
			++len;
		int* next = new int[len + 1];
		help::get_nextval(Pattern, next);

		int index = 0, i = 0, j = 0;
		while (Text[i] != '\0' && Pattern[j] != '\0')
		{
			if (Text[i] == Pattern[j])
			{
				++i;
				++j;
			}
			else
			{
				index += j - next[j];
				if (next[j] != -1)
					j = next[j];
				else
				{
					j = 0;
					++i;
				}
			}
		}

		delete[]next;
		if (Pattern[j] == '\0')
			return index;
		else
			return -1;
	}
#endif // UNICODE
#endif

#ifdef UNICODE
	#define OutputDebugStringFormat  OutputDebugStringFormatW
	#define getStringLeft  getStringLeftW
	#define StringFormat  StringFormatW
	#define NewGUID  NewGUIDW
#else
	#define OutputDebugStringFormat  OutputDebugStringFormatA
	#define getStringLeft  getStringLeftA
	#define StringFormat  StringFormatA
	#define NewGUID  NewGUIDA
#endif 

}

#endif