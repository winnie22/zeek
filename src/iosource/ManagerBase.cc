// See the file "COPYING" in the main distribution directory for copyright.

#include "ManagerBase.h"

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
#include "Manager.h"

#include "util.h"

#define DEFAULT_PREFIX "pcap"

using namespace iosource;

ManagerBase::WakeupHandler::WakeupHandler()
	{
	iosource_mgr->RegisterFd(flare.FD(), this);
	}

ManagerBase::WakeupHandler::~WakeupHandler()
	{
	iosource_mgr->UnregisterFd(flare.FD());
	}

void ManagerBase::WakeupHandler::Process()
	{
	flare.Extinguish();
	}

void ManagerBase::WakeupHandler::Ping(const std::string& where)
	{
	DBG_LOG(DBG_MAINLOOP, "Pinging WakeupHandler from %s", where.c_str());
	flare.Fire();
	}

ManagerBase::ManagerBase()
	{
	}

ManagerBase::~ManagerBase()
	{
	delete wakeup;

	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		(*i)->src->Done();
		delete (*i)->src;
		delete *i;
		}

	sources.clear();

	for ( PktDumperList::iterator i = pkt_dumpers.begin(); i != pkt_dumpers.end(); ++i )
		{
		(*i)->Done();
		delete *i;
		}

	pkt_dumpers.clear();
	}

void ManagerBase::InitPostScript()
	{
	wakeup = new WakeupHandler();
	}

void ManagerBase::RemoveAll()
	{
	// We're cheating a bit here ...
	dont_counts = sources.size();
	}

void ManagerBase::Wakeup(const std::string& where)
	{
	if ( wakeup )
		wakeup->Ping(where);
	}

void ManagerBase::FindReadySources(std::vector<IOSource*>* ready)
	{
	ready->clear();

	// Remove sources which have gone dry. For simplicity, we only
	// remove at most one each time.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		if ( ! (*i)->src->IsOpen() )
			{
			(*i)->src->Done();
			delete *i;
			sources.erase(i);
			break;
			}

	// If there aren't any sources and exit_only_after_terminate is false, just
	// return an empty set of sources. We want the main loop to end.
	if ( Size() == 0 && ( ! BifConst::exit_only_after_terminate || terminating ) )
		return;

	double timeout = -1;
	IOSource* timeout_src = nullptr;

	// Find the source with the next timeout value.
	for ( auto src : sources )
		{
		if ( src->src->IsOpen() )
			{
			double next = src->src->GetNextTimeout();
			if ( timeout == -1 || ( next >= 0.0 && next < timeout ) )
				{
				timeout = next;
				timeout_src = src->src;

				// If we found a source with a zero timeout, just return it immediately.
				// This is a fast optimization, but we want to make sure to go through
				// with the poll periodically to avoid starvation.
				if ( timeout == 0 && zero_timeout_count % 100 != 0 )
					{
					zero_timeout_count++;
					ready->push_back(timeout_src);
					return;
					}
				}
			}
		}

	zero_timeout_count = 1;

	// Call the appropriate poll method for what's available on the operating system.
	Poll(ready, timeout, timeout_src);
	}

void ManagerBase::ConvertTimeout(double timeout, struct timespec& spec)
	{
	// If timeout ended up -1, set it to some nominal value just to keep the loop
	// from blocking forever. This is the case of exit_only_after_terminate when
	// there isn't anything else going on.
	if ( timeout < 0 )
		{
		spec.tv_sec = 0;
		spec.tv_nsec = 1e8;
		}
	else
		{
		spec.tv_sec = static_cast<time_t>(timeout);
		spec.tv_nsec = static_cast<long>((timeout - spec.tv_sec) * 1e9);
		}
	}

void ManagerBase::Register(IOSource* src, bool dont_count)
	{
	// First see if we already have registered that source. If so, just
	// adjust dont_count.
	for ( SourceList::iterator i = sources.begin(); i != sources.end(); ++i )
		{
		if ( (*i)->src == src )
			{
			if ( (*i)->dont_count != dont_count )
				// Adjust the global counter.
				dont_counts += (dont_count ? 1 : -1);

			return;
			}
		}

	src->InitSource();
	Source* s = new Source;
	s->src = src;
	s->dont_count = dont_count;
	if ( dont_count )
		++dont_counts;

	sources.push_back(s);
	}

void ManagerBase::Register(PktSrc* src)
	{
	pkt_src = src;
	Register(src, false);
	}

static std::pair<std::string, std::string> split_prefix(std::string path)
	{
	// See if the path comes with a prefix telling us which type of
	// PktSrc to use. If not, choose default.
	std::string prefix;

	std::string::size_type i = path.find("::");
	if ( i != std::string::npos )
		{
		prefix = path.substr(0, i);
		path = path.substr(i + 2, std::string::npos);
		}

	else
		prefix= DEFAULT_PREFIX;

	return std::make_pair(prefix, path);
	}

PktSrc* ManagerBase::OpenPktSrc(const std::string& path, bool is_live)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet sources of the requested prefix.

	PktSrcComponent* component = 0;

	std::list<PktSrcComponent*> all_components = plugin_mgr->Components<PktSrcComponent>();

	for ( std::list<PktSrcComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		PktSrcComponent* c = *i;

		if ( c->HandlesPrefix(prefix) &&
		     ((  is_live && c->DoesLive() ) ||
		      (! is_live && c->DoesTrace())) )
			{
			component = c;
			break;
			}
		}


	if ( ! component )
		reporter->FatalError("type of packet source '%s' not recognized, or mode not supported", prefix.c_str());

	// Instantiate packet source.

	PktSrc* ps = (*component->Factory())(npath, is_live);
	assert(ps);

	if ( ! ps->IsOpen() && ps->IsError() )
		// Set an error message if it didn't open successfully.
		ps->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packet source of type %s for %s", component->Name().c_str(), npath.c_str());

	Register(ps);
	return ps;
	}


PktDumper* ManagerBase::OpenPktDumper(const string& path, bool append)
	{
	std::pair<std::string, std::string> t = split_prefix(path);
	std::string prefix = t.first;
	std::string npath = t.second;

	// Find the component providing packet dumpers of the requested prefix.

	PktDumperComponent* component = 0;

	std::list<PktDumperComponent*> all_components = plugin_mgr->Components<PktDumperComponent>();

	for ( std::list<PktDumperComponent*>::const_iterator i = all_components.begin();
	      i != all_components.end(); i++ )
		{
		if ( (*i)->HandlesPrefix(prefix) )
			{
			component = (*i);
			break;
			}
		}

	if ( ! component )
		reporter->FatalError("type of packet dumper '%s' not recognized", prefix.c_str());

	// Instantiate packet dumper.

	PktDumper* pd = (*component->Factory())(npath, append);
	assert(pd);

	if ( ! pd->IsOpen() && pd->IsError() )
		// Set an error message if it didn't open successfully.
		pd->Error("could not open");

	DBG_LOG(DBG_PKTIO, "Created packer dumper of type %s for %s", component->Name().c_str(), npath.c_str());

	pd->Init();
	pkt_dumpers.push_back(pd);

	return pd;
	}
