// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>
#include <sys/timerfd.h>

#include "IOSource.h"
#include "Net.h"
#include "PktSrc.h"
#include "PktDumper.h"
#include "plugin/Manager.h"
#include "broker/Manager.h"

#include "util.h"

using namespace iosource;

Manager::Manager() : ManagerBase()
	{
	DBG_LOG(DBG_MAINLOOP, "Using epoll main loop");

	event_queue = epoll_create1(EPOLL_CLOEXEC);
	if ( event_queue == -1 )
		reporter->FatalError("Failed to open epoll() file descriptor: %s", strerror(errno));

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if ( timerfd == -1 )
		reporter->FatalError("Failed to initialize timerfd: %s", strerror(errno));

	epoll_event event;
	memset(&event, 0, sizeof(epoll_event));
	event.events = EPOLLIN;

	if ( epoll_ctl(event_queue, EPOLL_CTL_ADD, timerfd, &event) != -1 )
		{
		DBG_LOG(DBG_MAINLOOP, "Added fd %d from Timerfd", timerfd);
		events.push_back({});
		}
	}

Manager::~Manager()
	{
	if ( timerfd != -1 )
		close(timerfd);

	if ( event_queue != -1 )
		close(event_queue);
	}

void Manager::RegisterFd(int fd, IOSource* src)
	{
	epoll_event event;
	memset(&event, 0, sizeof(epoll_event));
	event.events = EPOLLIN;
	event.data.fd = fd;

	int ret = epoll_ctl(event_queue, EPOLL_CTL_ADD, fd, &event);
	if ( ret != -1 )
		{
		DBG_LOG(DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
		events.push_back({});
		fd_map[fd] = src;
		Wakeup("RegisterFd");
		}
	else
		{
		DBG_LOG(DBG_MAINLOOP, "Failed to register fd %d from %s: %s", fd, src->Tag(), strerror(errno));
		}
	}

void Manager::UnregisterFd(int fd)
	{
	if ( fd_map.find(fd) != fd_map.end() )
		{
		int ret = epoll_ctl(event_queue, EPOLL_CTL_DEL, fd, NULL);
		if ( ret != -1 )
			DBG_LOG(DBG_MAINLOOP, "Unregistered fd %d", fd);

		events.pop_back();
		fd_map.erase(fd);

		Wakeup("UnregisterFd");
		}
	}

void Manager::Poll(std::vector<IOSource*>* ready, double timeout, IOSource* timeout_src)
	{
	// Because of the way timerfd works, you can't just set it to a zero
	// timeout. That deactivates the timer. That means if the timeout
	// passed in was zero, we need to pass that zero down to poll().
	// Otherwise, set it to -1 and let timerfd do its thing.
	int poll_timeout;
	if ( timeout != 0 )
		{
		struct itimerspec new_timeout = { 0, 0 };
		ConvertTimeout(timeout, new_timeout.it_value);
		timerfd_settime(timerfd, 0, &new_timeout, NULL);
		poll_timeout = -1;
		}
	else
		{
		struct itimerspec new_timeout = { 0, 0 };
		timerfd_settime(timerfd, 0, &new_timeout, NULL);
		poll_timeout = 0;
		}

	DBG_LOG(DBG_MAINLOOP, "poll timeout: %d", poll_timeout);

	int ret = epoll_wait(event_queue, events.data(), events.size(), poll_timeout);
	if ( ret == -1 )
		{
		if ( errno != EINTR )
			reporter->InternalWarning("Error calling epoll: %s", strerror(errno));
		}
	else if ( ret == 0 )
		{
		if ( timeout_src )
			ready->push_back(timeout_src);
		}
	else
		{
		for ( int i = 0; i < ret; i++ )
			{
			if ( events[i].data.fd == timerfd && events[i].events == EPOLLIN )
				{
				uint64_t elapsed;
				read(timerfd, &elapsed, 8);

				ready->clear();
				if ( timeout_src )
					ready->push_back(timeout_src);
				break;
				}
			else
				{
				auto entry = fd_map.find(events[i].data.fd);
				if ( entry != fd_map.end() )
					{
					if ( events[i].events == EPOLLIN )
						ready->push_back(entry->second);
					else if ( events[i].events == EPOLLERR || events[i].events == EPOLLHUP )
						reporter->InternalWarning(
							"Source %s returned an error from poll (0x%x)\n",
							entry->second->Tag(), events[i].events);
					}
				}
			}
		}
	}
