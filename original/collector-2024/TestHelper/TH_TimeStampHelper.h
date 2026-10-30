#pragma once
#include <Windows.h>
#include <sys/timeb.h>

//微秒级
class CHighResolutionTimeStampHelper
{
private:
	LONGLONG m__freq;
	LARGE_INTEGER m_begin;
	LARGE_INTEGER m_end;

public:
	long* m_plCost;

public:
	CHighResolutionTimeStampHelper():m_plCost(nullptr)
	{
		LARGE_INTEGER tmp;
		QueryPerformanceFrequency(&tmp);
		m__freq = tmp.QuadPart;
	}

	CHighResolutionTimeStampHelper(long * plCost):m_plCost(plCost)
	{
		assert(plCost != nullptr);
		new(this)CHighResolutionTimeStampHelper();
		m_plCost = plCost;
		QueryPerformanceCounter(&m_begin);
	}

	~CHighResolutionTimeStampHelper()
	{
		if (m_plCost)
		{
			QueryPerformanceCounter(&m_end);
			*m_plCost = (long)((m_end.QuadPart - m_begin.QuadPart) * 1000000 / m__freq);
		}
	}

	long GetCurrentTimeStamp()
	{
		LARGE_INTEGER nCurrent;
		QueryPerformanceCounter(&nCurrent);
		return (long)(nCurrent.QuadPart * 1000000 / m__freq);
	}
};