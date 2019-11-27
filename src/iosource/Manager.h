// See the file "COPYING" in the main distribution directory for copyright.

#pragma once

#include "zeek-config.h"

#include "ManagerBase.h"

#if defined(HAVE_EPOLL_H)
#include <sys/epoll.h>
#include <sys/timerfd.h>
#elif defined(HAVE_KQUEUE)
#include <sys/event.h>
#else
#include <poll.h>
#endif

#include <map>
#include <vector>

#include "IOSource.h"

namespace iosource {

/**
 * Main IOSource manager class. This class can (and should) be specialized
 * based on the support the OS provides for varying poll methods. The
 * implementation files for this class are broken by those poll methods.
 * The version that gets compiled is controlled by the CMakeLists file in
 * the iosource directory.
 */
class Manager : public ManagerBase {
public:
	/**
	 * Constructor.
	 */
	Manager();

	/**
	 * Destructor.
	 */
	~Manager();

	/**
	 * Registers a file descriptor and associated IOSource with the manager
	 * to be checked during FindReadySources.
	 *
	 * @param fd A file descriptor pointing at some resource that should be
	 * checked for readiness.
	 * @param src The IOSource that owns the file descriptor.
	 */
	void RegisterFd(int fd, IOSource* src) override;

	/**
	 * Unregisters a file descriptor from the FindReadySources checks.
	 */
	void UnregisterFd(int fd) override;

protected:

	/**
	 * Calls the appropriate poll method to gather a set of IOSources that are
	 * ready for processing.
	 *
	 * @param ready a vector used to return the ready sources.
	 * @param timeout the value to be used for the timeout of the poll. This
	 * should be a value relative to the current network time, not an
	 * absolute time value. This may be zero to cause an infinite timeout or
	 * -1 to force a very short timeout.
	 * @param timeout_src The source associated with the current timeout value.
	 * This is typically a timer manager object.
	 */
	void Poll(std::vector<IOSource*>* ready, double timeout, IOSource* timeout_src) override;

private:

	int event_queue = -1;
	std::map<int, IOSource*> fd_map;

#if defined(HAVE_EPOLL_H)
	std::vector<epoll_event> events;
#elif defined(HAVE_KQUEUE)
	// This is only used for the output of the call to kqueue in FindReadySources().
	// The actual events are stored as part of the queue.
	std::vector<struct kevent> events;
#else
	// Fall back to regular poll() if we don't have kqueue or epoll.
	std::vector<pollfd> events;
#endif

	int timerfd = -1;
};

}

extern iosource::Manager* iosource_mgr;
