/***************************************************************************
 *   Copyright (C) 2003-2006 by Grzegorz Rusin                             *
 *   grusin@gmail.com                                                      *
 *                                                                         *
 *   This program is free software; you can redistribute it and/or modify  *
 *   it under the terms of the GNU General Public License as published by  *
 *   the Free Software Foundation; either version 2 of the License, or     *
 *   (at your option) any later version.                                   *
 *                                                                         *
 *   This program is distributed in the hope that it will be useful,       *
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of        *
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the         *
 *   GNU General Public License for more details.                          *
 *                                                                         *
 *   You should have received a copy of the GNU General Public License     *
 *   along with this program; if not, write to the                         *
 *   Free Software Foundation, Inc.,                                       *
 *   59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.             *
 ***************************************************************************/

#include "prots.h"
#include "global-var.h"

ign::entry::entry(const sockaddr_storage &peer)
{
	memset(ip, 0, sizeof ip);
	if(peer.ss_family == AF_INET)
	{
		ip[10] = ip[11] = 0xff;
		memcpy(ip + 12, &((const sockaddr_in &)peer).sin_addr, 4);
	}
#ifdef HAVE_IPV6
	else if(peer.ss_family == AF_INET6)
		memcpy(ip, &((const sockaddr_in6 &)peer).sin6_addr, 16);
#endif
	when = NOW;
	count = 1;
	nextConn = 0;
}

int ign::entry::operator==(const entry &e) const
{
	return !memcmp(ip, e.ip, sizeof ip);
}

time_t ign::entry::creation()
{
	return when;
}

ign::ign()
{
	data.removePtrs();
	nextConn = 0;
}

ign::entry *ign::hit(const sockaddr_storage &peer)
{
	entry probe(peer);
	ptrlist<entry>::iterator p = data.find(probe);
	entry *e;

	if(p)
	{
		e = p;
		if(++e->count > set.PERIP_BURST_SIZE && e->nextConn <= NOW)
		{
			e->nextConn = NOW + set.PERIP_IGNORE_TIME;
			char addr[INET6_ADDRSTRLEN];
			const void *src = &((const sockaddr_in &)peer).sin_addr;
			int family = AF_INET;
#ifdef HAVE_IPV6
			if(peer.ss_family == AF_INET6) {
				family = AF_INET6;
				src = &((const sockaddr_in6 &)peer).sin6_addr;
			}
#endif
			net.send(HAS_N, "\002Ignoring %s for %d seconds\002",
			         inet_ntop(family, src, addr, sizeof addr), (int)set.PERIP_IGNORE_TIME);
		}
	}
	else
	{
		e = new entry(peer);
		data.add(e);
	}

	++count;
	if(count >= set.SYNFLOOD_MAX_CONNS && nextConn <= NOW)
	{
		net.send(HAS_N, "Synflood detected, not accepting conections for %d seconds", (int)set.SYNFLOOD_IGNORE_TIME);
		nextConn = NOW + set.SYNFLOOD_IGNORE_TIME;
	}
	return e;
}

void ign::expire()
{
	data.expire(set.PERIP_BURST_TIME, NOW);
	calcCount();
}

void ign::removeHit(int fd)
{
	sockaddr_storage peer;
	socklen_t size = sizeof peer;
	if(getpeername(fd, (sockaddr *)&peer, &size) != 0)
		return;
	entry probe(peer);
	ptrlist<entry>::iterator p = data.find(probe);
	if(p && --p->count <= 0)
		data.removeLink(p);
	calcCount();
}

void ign::calcCount()
{
	count = 0;

	ptrlist<entry>::iterator p = data.begin();

	while(p)
	{
		count += p->count;
		p++;
	}
}

