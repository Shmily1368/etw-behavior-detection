/********************************************************************
	Created:		2019-01-09
	Author:			chips;
	Version:		1.0.0(version);
	Description:	thread task to get visible window;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2018/01/09 |	1.0.0	 |	chips		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include "thread_task_base.h"

#include <windows.h>
#include <windef.h>

class GetVisibleWindowThreadTask : public BaseThreadTask
{
private:
	int m_nCoutTimes;
	int m_nIntervalTime;
	//int _cache_handle_time; timer线程中设置cache clean时间 目前为 3s
	static bool m_bCleanCacheHandleFlag;
	LONG m_lDesktopWidth;
	LONG m_lDesktopHeight;

	Mutex m_lock;
	//not used
	//Mutex _lock_handle;

	std::set<DWORD> m_setVwProcess;
	//cache handle of the windows
	//not used
	//std::unordered_set<HWND>	_vw_handle_set;
	std::set<HANDLE> m_setVwHandleBufNext;
	std::set<HANDLE> m_setVwHandleBufPrev;

	//please read article about how to make a callback function a member of class?: https://blogs.msdn.microsoft.com/oldnewthing/20140127-00/?p=1963
	static BOOL CALLBACK _StaticEnumWindowsProc(HWND hwnd, LPARAM lParam);
	BOOL _EnumWindowsProc(HWND hwnd);

	static BOOL CALLBACK _StaticEnumChildWindowsProc(HWND hwnd, LPARAM lParam);
	BOOL _EnumChildWindowsProc(HWND hwnd);

	virtual void _Excute();

	bool _WindowInScreen(const RECT& rect);
	bool _WindowVisible(HWND hwnd, RECT& rect, DWORD& visible, DWORD& toolbar);
	void _OnWindowVisible(HWND hwnd, DWORD pid, DWORD tid, RECT rect, DWORD visible, DWORD toolbar);
public:
	static void ActiveCacheFlag() { m_bCleanCacheHandleFlag = true; }
    bool InsertVisibleSet(DWORD pid);
    bool InsertHandleSet(const HWND& hwnd);
    bool EraseVisibleSet(DWORD pid);
    bool CleanHandleSet();
    bool QueryVisiblebyProcessId(DWORD pid);
    bool QueryHandleSet(const HWND& hwnd);
public:
	GetVisibleWindowThreadTask();
	~GetVisibleWindowThreadTask();

	virtual void Log();
	virtual void Init();
	virtual void AddData(EventRecord* record) override;
};