#include "stdafx.h"

#if defined( ETW_EVENT_RECORD_TEST)||defined (ETW_UNIT_RECORD_TEST)||defined (ETW_ONLINE_CALLBACK_EVENT_RECORD_TEST)||defined (ETW_FEATURE_RECORD_TEST)
CTHCsvRecordConfig_ETW g_thCRC(L"ETWFilterTest.csv");
#endif