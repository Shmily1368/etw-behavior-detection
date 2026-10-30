#include "stdafx.h"
#include "init_collector_factory.h"
#include "setting.h"
#include "init_collector.h"
#include "init_collector_online_parse.h"

InitCollectorFactory::InitCollectorFactory()
{
}

InitCollectorFactory::~InitCollectorFactory()
{
}

void InitCollectorFactory::Create() const
{
	InitCollector* collector = nullptr;
	switch (Setting::GetInstance().collector_mode())
	{
	case ONLINE_PARSE_MODE_STR:		collector = new InitCollectorOnlineParse(); break;
	default:	collector = nullptr;
	}

	InitCollector::_instance = collector;
}

void InitCollectorFactory::Recycle() const
{
	SAFE_DELETE(InitCollector::_instance);
}
