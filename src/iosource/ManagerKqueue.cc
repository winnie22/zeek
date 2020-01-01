// See the file "COPYING" in the main distribution directory for copyright.

#include "Manager.h"

#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <assert.h>

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
	DBG_LOG(DBG_MAINLOOP, "Using kqueue main loop");

	event_queue = kqueue();
	if ( event_queue == -1 )
		reporter->FatalError("Failed to initialize kqueue: %s", strerror(errno));
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
	struct kevent event;
	EV_SET(&event, fd, EVFILT_READ, EV_ADD, 0, 0, NULL);
	int ret = kevent(event_queue, &event, 1, NULL, 0, NULL);
	if ( ret != -1 )
		{
		events.push_back({});
		DBG_LOG(DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
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
		struct kevent event;
		EV_SET(&event, fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
		int ret = kevent(event_queue, &event, 1, NULL, 0, NULL);
		if ( ret != -1 )
			DBG_LOG(DBG_MAINLOOP, "Unregistered fd %d", fd);

		fd_map.erase(fd);

		Wakeup("UnregisterFd");
		}
	}

void Manager::Poll(std::vector<IOSource*>* ready, double timeout, IOSource* timeout_src)
	{
	struct timespec kqueue_timeout;
	ConvertTimeout(timeout, kqueue_timeout);

	int ret = kevent(event_queue, NULL, 0, events.data(), events.size(), &kqueue_timeout);
	if ( ret == -1 )
		{
		// Ignore interrupts since we may catch one during shutdown and we don't want the
		// error to get printed.
		if ( errno != EINTR )
			reporter->InternalWarning("Error calling kevent: %s", strerror(errno));
		}
	else if ( ret == 0 )
		{
		if ( timeout_src )
			ready->push_back(timeout_src);
		}
	else
		{
		// kevent returns the number of events that are ready, so we only need to loop
		// over that many of them.
		for ( int i = 0; i < ret; i++ )
			{
			if ( events[i].filter == EVFILT_READ )
				{
				std::map<int, IOSource*>::const_iterator it = fd_map.find(events[i].ident);
				if ( it != fd_map.end() )
					ready->push_back(it->second);
				}
			}
		}
	}
