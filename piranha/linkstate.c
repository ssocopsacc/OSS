/*
  Portions from if_lookup.c (Red Hat Cluster Manager):
  
  Copyright Red Hat, Inc. 2002
  Copyright Mission Critical Linux, 2000

  Portions from ethtool.c (ethtool):
  
  Copyright (C) 1998 David S. Miller (davem@dm.cobaltmicro.com)
  Portions Copyright 2001 Sun Microsystems
  Kernel 2.4 update Copyright 2001 Jeff Garzik <jgarzik@mandrakesoft.com>
  Wake-on-LAN,natsemi,misc support by Tim Hockin <thockin@sun.com>
  Portions Copyright 2002 Intel
  do_test support by Eli Kupermann <eli.kupermann@intel.com>
  ETHTOOL_PHYS_ID support by Chris Leech <christopher.leech@intel.com>
  e1000 support by Scott Feldman <scott.feldman@intel.com>
  e100 support by Wen Tao <wen-hwa.tao@intel.com>

  This program is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by the
  Free Software Foundation; either version 2, or (at your option) any
  later version.

  This program is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; see the file COPYING.  If not, write to the
  Free Software Foundation, Inc.,  675 Mass Ave, Cambridge, 
  MA 02139, USA.
*/

/** @file
 * Determine the state of an ethernet device holding a given IP
 * address... (Does not support bonded drivers, nor do I care)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/param.h>
#include <errno.h>
#include <netdb.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <linux/types.h>
#include <linux/sockios.h>

/* RHEL3 needs this */
#define u32 __u32
#define u16 __u16
#define u8 __u8

#include <linux/ethtool.h>
#include <linux/mii.h>
#include <net/if.h>

static int get_link_state(int fd, struct ifreq *ifr);

/**
 * Find a network interface and its link state, given an IP
 * address or hostname.
 *
 * @param ip_name	IP address or hostname to check against.
 */
int
ip_check_link(struct in_addr mon_addr)
{
	int sockfd, len, lastlen;
	char *cptr;
	struct ifconf ifc;
	struct ifreq *ifr, flags;
	int i, ret;

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockfd < 0)
		return (1);

	lastlen = 0;
	len = 100 * sizeof (struct ifreq);
	for (;;) {
		ifr = (struct ifreq *) malloc(len);
		ifc.ifc_len = len;
		ifc.ifc_buf = (char *) ifr;
		if (ioctl(sockfd, SIOCGIFCONF, &ifc) < 0) {
			if (errno != EINVAL || lastlen != 0) {
				free(ifr);
				close(sockfd);
				return -1;
			}
		} else {
			if (ifc.ifc_len == lastlen)
				break;	/* success, len has not changed */
			lastlen = ifc.ifc_len;
		}
		len += 10 * sizeof (struct ifreq);
		free(ifr);
	}

	len = (int) ifc.ifc_len / sizeof (struct ifreq);
	for (i = 0; i < len; i++) {

		if (ifr[i].ifr_addr.sa_family != AF_INET)
			continue;

		/*
		 * Ignore channel-bonded slave interfaces.
		 */
		memset(&flags, 0, sizeof (flags));
		strcpy(flags.ifr_name, ifr->ifr_name);
		if (ioctl(sockfd, SIOCGIFFLAGS, &flags)) {
			close(sockfd);
			return (1);
		}

		if (flags.ifr_flags & IFF_SLAVE)
			continue;

		/*
		 * Deal with aliases
		 */
		if ((cptr = strchr(ifr[i].ifr_name, ':')) != NULL)
			*cptr = 0;

		if (memcmp(&((struct sockaddr_in *) &ifr[i].ifr_addr)->sin_addr,
			   &mon_addr, sizeof (struct in_addr)))
			continue;

		/* if it's not up, the link isn't either. */
		if (!(flags.ifr_flags & IFF_UP))
			return 0;

		/* Found the interface -- see if its link state is up or
		   down */
		ret = get_link_state(sockfd, &ifr[i]);
		free(ifr);
		close(sockfd);

		return (ret);
	}

	free(ifr);
	close(sockfd);
	return -1;
}


/* Shamelessly ripped from ethtool. */
static int
get_link_state(int fd, struct ifreq *ifr)
{
    		int socId = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    		if (socId < 0) {
			return 0;
		}

    		struct ifreq if_req;
    		(void) strncpy(if_req.ifr_name, ifr->ifr_name, sizeof(if_req.ifr_name));
    		int rv = ioctl(socId, SIOCGIFFLAGS, &if_req);
    		close(socId);

    		if ( rv == -1) {
			return 0;
		}

    		if((if_req.ifr_flags & IFF_UP) && (if_req.ifr_flags & IFF_RUNNING)) {
			return 1;
		} else {
			return 0;
		}
	/* Any other errors: no link? */
	return 0;
}
