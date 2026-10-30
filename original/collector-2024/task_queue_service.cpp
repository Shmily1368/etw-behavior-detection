#include "stdafx.h"
#include "task_queue_service.h"

TaskQueueService::TaskQueueService()
{

}

TaskQueueService::~TaskQueueService()
{

}

void TaskQueueService::Start()
{
	_stop_flag = false;
	m_threadWorker = std::thread(std::bind(&TaskQueueService::_Excute, this));
}

void TaskQueueService::Stop()
{
	_stop_flag = true;
	m_signal.NotifyOne();
	if (m_threadWorker.joinable())
	{
		m_threadWorker.join();
	}
}

void TaskQueueService::AddTask(std::function<void()> task, std::function<void()> callback /*= nullptr*/)
{
	TaskQueueItem item;
	item.task = task;
	item.callback = callback;
	_task_queue.enqueue(item);
	m_signal.NotifyOne();
}

void TaskQueueService::_Excute()
{
	TaskQueueItem item;
	while (!_stop_flag)
	{
		if (_task_queue.try_dequeue(item))
		{
			if (item.task)	item.task();
			if (item.callback)	item.callback();
		}
		else
		{
			m_signal.Wait();
		}
	}
}
