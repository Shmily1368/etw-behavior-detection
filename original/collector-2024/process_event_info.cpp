#include "stdafx.h"
#include "process_event_info.h"

std::unordered_map<DWORD, process_event_info> process_map::g_umapPid2ProcessInfo;