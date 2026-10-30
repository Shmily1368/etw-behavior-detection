#pragma once
#include <Windows.h>
#include <xstring>
#include <Shlwapi.h>

#define MEMORYFILE_FLAG "MF_V0"
#define MEMORYFILE_V0_HEADLENGTH 16
#define MEMORYFILE_V0_SIZELENGTH 4
#define MEMORYFILE_V0_BASESIZE 10240

/*内存映射文件辅助类*/
class CMemoryFileHelper
{
public:
	CMemoryFileHelper(LPCTSTR lpFile)
	{
		SetFilePath(lpFile);
		InitFile();
	}

	~CMemoryFileHelper()
	{
		ClearHandle();
	}

	BOOL InitFile()
	{
		if (PathFileExists(GetFilePath().c_str()))
		{
			return TRUE;
		}
		else
		{
			HANDLE hFile = CreateFile(GetFilePath().c_str(), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
			if (hFile)
			{
				DWORD dwWrited = 0;
				char szTemp[MEMORYFILE_V0_BASESIZE] = { 0 };
				//strcpy_s(szTemp, MEMORYFILE_FLAG);
				memcpy(szTemp, MEMORYFILE_FLAG, sizeof(MEMORYFILE_FLAG));
				WriteFile(hFile, szTemp, MEMORYFILE_V0_BASESIZE, &dwWrited, NULL);
				CloseHandle(hFile);
				return TRUE;
			}
			else
				return FALSE;
		}
	}

	BOOL InitFileMemory()
	{
		//if (!PathFileExists(GetFilePath().c_str()))
		//{
		//	HANDLE hFile = CreateFile(GetFilePath().c_str()
		//		, GENERIC_WRITE, FILE_SHARE_WRITE , NULL
		//		, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
		//	if (hFile)
		//		CloseHandle(hFile);
		//	else
		//		return FALSE;
		//}

		m_hFile = CreateFile(GetFilePath().c_str(), GENERIC_READ | GENERIC_WRITE
			, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL
			, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
		if (!m_hFile)
			return FALSE;

		DWORD size_low, size_high;
		size_low = GetFileSize(m_hFile, &size_high);
		m_dwSize = size_low;

		m_hMapFile = CreateFileMapping(m_hFile, NULL, PAGE_READWRITE
			, size_high, size_low, NULL);
		if (m_hMapFile == INVALID_HANDLE_VALUE)
		{
			CloseHandle(m_hFile);
			return FALSE;
		}

		m_pf = MapViewOfFile(m_hMapFile, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
		if (!m_pf)
		{
			CloseHandle(m_hMapFile);
			CloseHandle(m_hFile);
			return FALSE;
		}
		GetSizeRecord();
		return TRUE;
	}

	BOOL AppendData(LPCSTR lpData, const DWORD dwDataSize)
	{
		DWORD dwCurrent = 0;
		memcpy(&dwCurrent, (LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, MEMORYFILE_V0_SIZELENGTH);
		if (dwDataSize + dwCurrent < m_dwSize - MEMORYFILE_V0_HEADLENGTH - MEMORYFILE_V0_SIZELENGTH)
		{
			//现有大小可以存储
		}
		else
		{
			//需要扩充文件大小
			do
			{
				ClearMapHandle();
				//按照现有文件大小扩大一倍的方式进行扩充
				zeroFillFile(m_hFile, m_dwSize, m_dwSize);
				ClearFileHandle();
				InitFileMemory();
			} while (dwDataSize + dwCurrent > m_dwSize - MEMORYFILE_V0_HEADLENGTH - MEMORYFILE_V0_SIZELENGTH);
		}

		if (dwCurrent == 0)
		{
			memcpy((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, &dwDataSize, MEMORYFILE_V0_SIZELENGTH);
			memcpy((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH + MEMORYFILE_V0_SIZELENGTH, lpData, dwDataSize);
			m_dwSizeRecord = dwDataSize;
		}
		else
		{
			DWORD dwTemp = dwDataSize + dwCurrent;
			memcpy((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, &dwTemp, MEMORYFILE_V0_SIZELENGTH);
			memcpy((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH + MEMORYFILE_V0_SIZELENGTH + dwCurrent, lpData, dwDataSize);
			m_dwSizeRecord = dwTemp;
		}
		return TRUE;
	}

	BOOL RemoveDataFromEnd(LPSTR lpData, DWORD& dwDataSize)
	{
		DWORD dwCurrent = 0;
		memcpy(&dwCurrent, (LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, MEMORYFILE_V0_SIZELENGTH);
		if (dwCurrent == 0)
			return FALSE;
		if (dwDataSize > dwCurrent)
		{
			dwDataSize = dwCurrent;
		}
		DWORD dwCurrentNew = dwCurrent - dwDataSize;
		memcpy(lpData, (LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH + MEMORYFILE_V0_SIZELENGTH + dwCurrent - dwDataSize, dwDataSize);
		memcpy((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, &dwCurrentNew, MEMORYFILE_V0_SIZELENGTH);
		memset((LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH + MEMORYFILE_V0_SIZELENGTH + dwCurrentNew, 0, dwDataSize);
		m_dwSizeRecord = dwCurrentNew;
		return TRUE;
	}

	void ClearHandle()
	{
		if (m_pf)
		{
			UnmapViewOfFile(m_pf);
			m_pf = nullptr;
		}
		if (m_hMapFile)
		{
			CloseHandle(m_hMapFile);
			m_hMapFile = nullptr;
		}
		if (m_hFile)
		{
			CloseHandle(m_hFile);
			m_hFile = nullptr;
		}
	}
	void ClearMapHandle()
	{
		if (m_pf)
		{
			UnmapViewOfFile(m_pf);
			m_pf = nullptr;
		}
		if (m_hMapFile)
		{
			CloseHandle(m_hMapFile);
			m_hMapFile = nullptr;
		}
	}
	void ClearFileHandle()
	{
		if (m_hFile)
		{
			CloseHandle(m_hFile);
			m_hFile = nullptr;
		}
	}
	DWORD GetSizeRecord()
	{
		memcpy(&m_dwSizeRecord, (LPBYTE)m_pf + MEMORYFILE_V0_HEADLENGTH, MEMORYFILE_V0_SIZELENGTH);
		return m_dwSizeRecord;
	}

	void SetFilePath(LPCTSTR lpFile) { m_strFilePath = lpFile; }
	std::wstring GetFilePath() { return m_strFilePath; }
private:

	BOOL zeroFillFile(HANDLE file, size_t startPos, size_t size)
	{
		if (file == INVALID_HANDLE_VALUE)
			return false;
		if (size == 0)
			return TRUE;

		LARGE_INTEGER position;
		position.QuadPart = startPos;
		if (!SetFilePointerEx(file, position, nullptr, FILE_BEGIN))
			return FALSE;

		static const char zeros[4096] = { 0 };
		while (size >= sizeof(zeros)) {
			DWORD bytesWritten = 0;
			if (!WriteFile(file, zeros, sizeof(zeros), &bytesWritten, nullptr))
				return FALSE;
			size -= bytesWritten;
		}
		if (size > 0) {
			DWORD bytesWritten = 0;
			if (!WriteFile(file, zeros, (DWORD)size, &bytesWritten, nullptr))
				return FALSE;
		}
		return true;
	}

	std::wstring m_strFilePath;
	HANDLE m_hFile;
	HANDLE m_hMapFile;
	void* m_pf;
	DWORD m_dwSize;
	DWORD m_dwSizeRecord;
};