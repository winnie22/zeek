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
	DBG_LOG(DBG_MAINLOOP, "Using poll main loop");

	timerfd = timerfd_create(CLOCK_MONOTONIC, 0);
	if ( timerfd == -1 )
		reporter->FatalError("Failed to initialize timerfd: %s", strerror(errno));

	pollfd pfd;
	pfd.fd = timerfd;
	pfd.events = POLLIN;
	events.push_back(pfd);
	DBG_LOG(DBG_MAINLOOP, "Added fd %d from Timerfd", timerfd);
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
	auto entry = std::find_if(events.begin(), events.end(),
		[fd](const pollfd &entry) -> bool { return entry.fd == fd; });
	if ( entry == events.end() )
		{
		DBG_LOG(DBG_MAINLOOP, "Registered fd %d from %s", fd, src->Tag());
		fd_map[fd] = src;

		pollfd pfd;
		pfd.fd = fd;
		pfd.events = POLLIN;
		events.push_back(pfd);

		Wakeup("RegisterFd");
		}
	}

void Manager::UnregisterFd(int fd)
	{
	auto entry = std::find_if(events.begin(), events.end(),
		[fd](const pollfd &entry) -> bool { return entry.fd == fd; });

	if ( entry != events.end() )
		{
		DBG_LOG(DBG_MAINLOOP, "Unregistered fd %d", fd);
		events.erase(entry);
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

	int ret = poll(events.data(), events.size(), poll_timeout);
	if ( ret == -1 )
		{
		if ( errno != EINTR )
			reporter->InternalWarning("Error calling poll: %s", strerror(errno));
		}
	else if ( ret == 0 )
		{
		if ( timeout_src )
			ready->push_back(timeout_src);
		}
	else
		{
		for ( auto pfd : events )
			{
			if ( pfd.fd == timerfd && pfd.revents == POLLIN )
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
				auto entry = fd_map.find(pfd.fd);
				if ( entry != fd_map.end() )
					{
					if ( pfd.revents == pfd.events )
						ready->push_back(entry->second);
					else if ( pfd.revents == POLLNVAL )
						reporter->InternalWarning(
							"File descriptor %d was closed during poll()\n", pfd.fd);
					else if ( pfd.revents == POLLERR || pfd.revents == POLLHUP )
						reporter->InternalWarning(
							"Source %s returned an error from poll (0x%x)\n",
							entry->second->Tag(), pfd.revents);
					}
				}
			}
		}
	}
