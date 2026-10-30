/********************************************************************
	Created:		2019-04-08
	Author:			xuduo;
	Version:		1.0.0(version);
	Description:	预编译头文件;
----------------------------------------------------------------------------

----------------------------------------------------------------------------
  Remark         :
----------------------------------------------------------------------------
  Change History :
  <Date>     | <Version> | <Author>       | <Description>
----------------------------------------------------------------------------
  2019-04-08 |	1.0.0	 |	xuduo		  | Create file
----------------------------------------------------------------------------
*********************************************************************/

#pragma once
#include <functional>
using namespace std;

#include <WinSock2.h>
#include <Windows.h>
#include "platform.h"
#include "common.h"
#include "global_enum_def.h"
#include "assist_macro.h"

#include "auto_lock.h"
#include "mutex.h"
#include "spin_lock.h"
#include "rwlock.h"
#include "semaphore.h"

#include "logger_record.h"
#include "string_util.h"

#include <fstream>
#include <functional>
#include"../TestHelper/TH_Control.h"
//#include "../TestHelper/PykMgr.h "


#if defined( ETW_EVENT_RECORD_TEST)||defined (ETW_UNIT_RECORD_TEST)||defined (ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST)||defined (ETW_FEATURE_RECORD_TEST)
#include "../TestHelper/TH_CSVRecordConfig.h"
extern CTHCsvRecordConfig_ETW g_thCRC;
#endif // MAGIC_FILE_TIMECOST_TEST

typedef int int32;
typedef unsigned int uint32;
typedef long long int64;
typedef unsigned long long uint64;

#include <tchar.h>
