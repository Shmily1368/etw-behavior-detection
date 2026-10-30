#pragma once

#include "thread_task_base.h"
#include "event_record.h"

class ParseAutorunThreadTask : public BaseThreadTask
{
private:
	virtual void _Excute();
public:
	ParseAutorunThreadTask();
	~ParseAutorunThreadTask();

	virtual void Log();
	virtual void Init();
	
};
