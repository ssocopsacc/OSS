/*
** ipvs_exec.c -- Run IPVS commands
**
** Red Hat Clustering Tools 
** Copyright 1999 Red Hat Inc.
**
** Author: Erik Troan <ewt@redhat.com>
**
** 5-01-2007 - split from nanny.c by lhh@redhat.com
*/

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <popt.h>
#include <setjmp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <sys/signal.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <math.h>		/* for pow() */
#include <time.h>
#include <sys/types.h>
#include <regex.h>

#include "globals.h"
#include "util.h"
#include "nanny.h"

#define _(a) (a)
#define N_(a) (a)


int
runCommand (char *cmd, int flags, char **argv, int log_flag)
{
	int child;
	int status;
	int rc;
	int log_it;
	sigset_t sigs;

	log_it = log_flag;
	if (flags & NANNY_FLAG_VERBOSE)
		log_it = -1;

	if (log_it)
		logArgv (flags, argv);

	if (flags & NANNY_FLAG_NORUN)
		return 0;

	if (!(child = fork ())) {
		sigfillset(&sigs);
		sigprocmask(SIG_UNBLOCK, &sigs, NULL);
		for (rc = 1; rc < _NSIG; rc++)
			signal(rc, SIG_DFL);

		execv (argv[0], argv);
		exit (1);
	}

	rc = waitpid (child, &status, 0);

	if (!WIFEXITED (status) || WEXITSTATUS (status)) {
		piranha_log (flags, (char *) "%s command failed!", cmd);
		return 1;
	}

	return 0;
}

int
shutdownDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	     struct in_addr *remoteAddr, int rport, int service_type, 
	     int fwmark, int use_udp)
{

	char *argv[40];
	char **argp = argv;
	char virtName[80];
	char remoteName[80];
	char fwmStr[20];
	int rc = 0;

	if (service_type == SERV_LVS) {
		/* Virtual Server */

		*argp++ = ipvsadm;
		*argp++ = (char *) "-d";

		if (fwmark) {
			sprintf (fwmStr, "%d", fwmark);
			*argp++ = (char *) "-f";
			*argp++ = fwmStr;
		} else {
			sprintf (virtName, "%s:%d", virtualAddress, port);
			if (use_udp)
				*argp++ = (char *) "-u";
			else
				*argp++ = (char *) "-t";
			*argp++ = virtName;
		}

		*argp++ = (char *) "-r";
		sprintf (remoteName, "%s:%d", inet_ntoa (*remoteAddr), rport);
		*argp++ = remoteName;
		*argp = NULL;

		rc = runCommand (ipvsadm, flags, argv, -1);

	} 
	/* Nothing needs to be done for FOS */
	return rc;
}

int
adjustDevice (int flags, char *ipvsadm, char *virtualAddress, int port,
	      struct in_addr *remoteAddr, int rport, char *routingMethod, int weight,
	      int fwmark, int use_udp)
{
	char *argv[40];
	char **argp = argv;
	char virtName[80];
	char remoteName[80];
	char weightStr[20];
	char fwmStr[20];

	sprintf (weightStr, "%d", weight);

	*argp++ = ipvsadm;
	*argp++ = (char *) "-e";

	if (fwmark) {
		sprintf (fwmStr, "%d", fwmark);
		*argp++ = (char *) "-f";
		*argp++ = fwmStr;
	} else {
		sprintf (virtName, "%s:%d", virtualAddress, port);
		if (use_udp)
			*argp++ = (char *) "-u";
		else
			*argp++ = (char *) "-t";
		*argp++ = virtName;
	}

	*argp++ = (char *) "-r";
	sprintf (remoteName, "%s:%d", inet_ntoa (*remoteAddr), rport);
	*argp++ = remoteName;
	*argp++ = routingMethod;
	*argp++ = (char *) "-w";
	*argp++ = weightStr;
	*argp = NULL;

	return runCommand (ipvsadm, flags, argv, 0);
}

int
bringUpDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	    struct in_addr *remoteAddr, int rport, char *routingMethod,
	    int weight, int service_type, int fwmark, int use_udp)
{

	char *argv[40];
	char **argp = argv;
	char virtName[80];
	char remoteName[80];
	char weightStr[20];
	char fwmStr[20];
	int rc = 0;

	if (service_type == SERV_LVS) {
		/* Virtual Server */

		sprintf (weightStr, "%d", weight);

		*argp++ = ipvsadm;
		*argp++ = (char *) "-a";

		if (fwmark) {
			sprintf (fwmStr, "%d", fwmark);
			*argp++ = (char *) "-f";
			*argp++ = fwmStr;
		} else {
			sprintf (virtName, "%s:%d", virtualAddress, port);
			if (use_udp)
				*argp++ = (char *) "-u";
			else
				*argp++ = (char *) "-t";
			*argp++ = virtName;
		}

		*argp++ = (char *) "-r";
		sprintf (remoteName, "%s:%d", inet_ntoa (*remoteAddr), rport);
		*argp++ = remoteName;
		*argp++ = routingMethod;
		*argp++ = (char *) "-w";
		*argp++ = weightStr;
		*argp = NULL;

		rc = runCommand (ipvsadm, flags, argv, -1);
	}
	/* Nothing needs to be done for FOS */
	return rc;
}


