#include "stdafx.h"
#include "thread_task_get_visiblewindow.h"
#include "global_enum_def.h"
#include "setting.h"
#include "init_collector.h"
#include "tool_functions.h"
#include "filter.h"
#include "init_collector_online_parse.h"

#include <Windows.h>
#include <windef.h>

GetVisibleWindowThreadTask::GetVisibleWindowThreadTask()
	: BaseThreadTask(GET_VISIBLE_WINDOW_TASK_MODE)
	, m_lDesktopWidth(0)
	, m_lDesktopHeight(0)
{
	m_nCoutTimes = 0;
	//_interval_time = Setting::GetInstance().GetInt("get_visiblewindow_task_interval");
	m_nIntervalTime = Setting::GetInstance().visible_window_task_interval();
}

GetVisibleWindowThreadTask::~GetVisibleWindowThreadTask()
{

}

BOOL CALLBACK GetVisibleWindowThreadTask::_StaticEnumWindowsProc(HWND hwnd, LPARAM lParam)
{
	GetVisibleWindowThreadTask *pThis = reinterpret_cast<GetVisibleWindowThreadTask*>(lParam);
	return pThis->_EnumWindowsProc(hwnd);
}

BOOL GetVisibleWindowThreadTask::_EnumWindowsProc(HWND hwnd)
{
	DWORD process_id = 0, thread_id = 0;
	thread_id = GetWindowThreadProcessId(hwnd, &process_id);
	if (Filter::GetInstance().IsSuperWhiteListProcessEx(process_id))	return TRUE;
	if (process_id == InitCollectorOnlineParse::m_dwApplicationFrameHostPid)
	{
		EnumChildWindows(hwnd, _StaticEnumChildWindowsProc, reinterpret_cast<LPARAM>(this));
		return TRUE;
	}

	if (QueryVisiblebyProcessId(process_id))
	{
		return TRUE;
	}

	RECT rect;
	DWORD visible, toolbar;
	if (!_WindowVisible(hwnd, rect, visible, toolbar))
	{
		return TRUE;
	}

	_OnWindowVisible(hwnd, process_id, thread_id, rect, visible, toolbar);
	return TRUE;
}

BOOL CALLBACK GetVisibleWindowThreadTask::_StaticEnumChildWindowsProc(HWND hwnd, LPARAM lParam)
{
	GetVisibleWindowThreadTask *pThis = reinterpret_cast<GetVisibleWindowThreadTask*>(lParam);
	return pThis->_EnumChildWindowsProc(hwnd);
}

BOOL GetVisibleWindowThreadTask::_EnumChildWindowsProc(HWND hwnd)
{
	DWORD process_id = 0, thread_id = 0;
	thread_id = GetWindowThreadProcessId(hwnd, &process_id);
	if (Filter::GetInstance().IsSuperWhiteListProcess(process_id))	return TRUE;
	if (process_id == InitCollectorOnlineParse::m_dwApplicationFrameHostPid)	return TRUE;

    if (QueryVisiblebyProcessId(process_id))
	{
		return TRUE;
	}

	RECT rect;
	DWORD visible, toolbar;
	if (!_WindowVisible(hwnd, rect, visible, toolbar))
	{
		return TRUE;
	}

	_OnWindowVisible(hwnd, process_id, thread_id, rect, visible, toolbar);
	return TRUE;
}

void GetVisibleWindowThreadTask::_Excute()
{
    // add by zxw on 20210111 wait 10s 否则无法获取UUID
    Sleep(MS_TEN_SECOND);

	while (!_stop_flag) 
	{
		//get system resolution radio
		if (m_lDesktopWidth == 0 && m_lDesktopHeight == 0)
		{
			//_desktop_width = GetSystemMetrics(SM_CXSCREEN);
			//_desktop_height = GetSystemMetrics(SM_CYSCREEN);
            ToolFunctions::GetScreenRect(m_lDesktopWidth, m_lDesktopHeight);

			EventRecord* event_record = EventRecordManager::GetInstance().ParseVisibleWindowStruct(0, 0, 0, 0, 0, m_lDesktopWidth, m_lDesktopHeight, 0, 0);
			InitCollector::GetCollector()->PushSendRecord((EventRecord*)event_record);
		}

		/*
		Enumerates all top-level windows on the screen by passing the handle to each window,
		in turn, to an application-defined callback function. EnumWindows continues
		until the last top-level window is enumerated or the callback function returns FALSE.
		*/
		std::copy(m_setVwHandleBufNext.begin(), m_setVwHandleBufNext.end(), std::inserter(m_setVwHandleBufPrev, m_setVwHandleBufPrev.begin()));
		m_setVwHandleBufNext.clear();
		{
			//AutoLock lock(_lock);
			EnumWindows(_StaticEnumWindowsProc, reinterpret_cast<LPARAM>(this));
		}
		m_setVwHandleBufPrev.clear();

		Sleep(m_nIntervalTime);
		m_nCoutTimes++;

		if (m_nCoutTimes % 1000 == 0) 
		{
			m_nCoutTimes = 0;
			WriteLog4cPlus(INFO_LEVEL, L"GetVisibleWindowThreadTask::_Excute: vw_process_set =  %d", m_setVwProcess.size());
		}
	}
}

bool GetVisibleWindowThreadTask::_WindowInScreen(const RECT& rect)
	{
	//这样我们认为是被最小化的window;
	if (rect.bottom < 0 && rect.right < 0)
	{
		return true;
	}

	if ((rect.right - rect.left) <= 2 || (rect.bottom - rect.top) <= 2)
	{
		return false;
	}

	if (rect.top >= m_lDesktopHeight || rect.bottom <= 0 ||
		rect.left >= m_lDesktopWidth || rect.right <= 0)
	{
		return false;
	}

	//取屏幕内部分判断长宽;
	LONG actual_left = max((LONG)0, rect.left);
	LONG actual_right = min(m_lDesktopWidth, rect.right);
	LONG actual_top = max((LONG)0, rect.top);
	LONG actual_bottom = min(m_lDesktopHeight, rect.bottom);
	if ((actual_right - actual_left) <= 2 || (actual_bottom - actual_top) <= 2)
	{
		return false;
	}

	return true;
}

bool GetVisibleWindowThreadTask::_WindowVisible(HWND hwnd, RECT& rect, DWORD& visible, DWORD& toolbar)
{
	LONG style = GetWindowLong(hwnd, GWL_STYLE);
	LONG ex_style = GetWindowLong(hwnd, GWL_EXSTYLE);

	if (style == 0)
	{
		return false;
	}

	visible = (style & WS_VISIBLE) != 0 ? 1 : 0;
	toolbar = ToolFunctions::WindowIconic(hwnd) ? 1 : 0;
	DWORD layered = (ex_style & WS_EX_LAYERED) != 0 ? 1 : 0;

	if (visible == 0 && toolbar == 0)
	{
		return false;
	}

	if (layered != 0)
	{
		BYTE alpha = 0;
		DWORD dw_flag = 0;
		GetLayeredWindowAttributes(hwnd, NULL, &alpha, &dw_flag);
		if (((dw_flag & LWA_ALPHA) != 0) && alpha == 0)	//the window is completely transparent;
		{
			return false;
		}
	}

	HWND owner_hwnd = GetWindow(hwnd, GW_OWNER);
	if (owner_hwnd != 0)
	{
		LONG owner_style = GetWindowLong(owner_hwnd, GWL_STYLE);
		DWORD owner_visible = (owner_style & WS_VISIBLE) != 0 ? 1 : 0;
		DWORD owner_toolbar = ToolFunctions::WindowIconic(owner_hwnd) ? 1 : 0;
		if (owner_visible == 0 && owner_toolbar == 0)
		{
			return false;
		}
	}

	GetWindowRect(hwnd, &rect);
	if (!_WindowInScreen(rect))
	{
		return false;
	}

	return true;
}

void GetVisibleWindowThreadTask::_OnWindowVisible(HWND hwnd, DWORD pid, DWORD tid, RECT rect, DWORD visible, DWORD toolbar)
{
	if (m_setVwHandleBufPrev.find(hwnd) != m_setVwHandleBufPrev.end())
	{
		pair<DWORD, LLONG> key(pid, (LLONG)hwnd);
		EventRecord* event_record = EventRecordManager::GetInstance().ParseVisibleWindowStruct(pid, tid, (LLONG)hwnd, rect.left, rect.top, rect.right, rect.bottom, visible, toolbar);
		InitCollector::GetCollector()->PushSendRecord(event_record);

		//_vw_process_set.insert(pid);
        InsertVisibleSet(pid);
	}
	else
	{
		m_setVwHandleBufNext.insert(hwnd);
	}
}

bool GetVisibleWindowThreadTask::InsertVisibleSet(DWORD pid) 
{
    AutoLock lock(m_lock);
    auto iter_f = m_setVwProcess.find(pid);
    if (iter_f == m_setVwProcess.end()) {
        m_setVwProcess.insert(pid);
    }   
    return true;
}

bool GetVisibleWindowThreadTask::EraseVisibleSet(DWORD pid) 
{
    AutoLock lock(m_lock);
    auto iter_f = m_setVwProcess.find(pid);
    if (iter_f != m_setVwProcess.end()) {
        m_setVwProcess.erase(iter_f);
    }
    return true;
}

bool GetVisibleWindowThreadTask::QueryVisiblebyProcessId(DWORD pid) 
{
    AutoLock lock(m_lock);
    auto iter_f = m_setVwProcess.find(pid);
    if (iter_f != m_setVwProcess.end()) {
        return true;
    }
    return false;
}

void GetVisibleWindowThreadTask::Log()
{
	WriteLog4cPlus(INFO_LEVEL, L"VisibleWindowProcessCount:  %d", m_setVwProcess.size());
}

void GetVisibleWindowThreadTask::Init()
{
	WriteLog4cPlus(INFO_LEVEL, L"InitVisibleWindowRecord");
}

void GetVisibleWindowThreadTask::AddData(EventRecord* record)
{
	const EventIdentifier& identifier = record->get_event_identifier_();
	if (identifier.provider_id() != ETWProcess || identifier.opcode() != EM_ProcessEventOPC::ProcessEnd)
	{
		return;
	}

    EraseVisibleSet(record->get_process_id_());
}
