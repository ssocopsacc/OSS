/* LVS - Linux Virtual Server
**
** Red Hat Clustering Tools 
** Copyright 1999 Red Hat, Inc.
**
** Author: Erik Troan <ewt@redhat.com> 
**
**
** This software may be freely redistributed under the terms of the GNU
** public license.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
**
**
** MODIFICATION HISTORY
**
** 9/xx/1999    1.0 -   Erik Troan <ewt@redhat.com>
**              1.21    Initial release and repairs
**
** 11/4/1999    1.22    Mike Wangsmo <wanger@redhat.com>
**                      Added persistent code
**
** 12/19/1999   1.23    Phil "Bryce" Copeland <copeland@redhat.com>
**                      64 bit and typecast changes
**
** 1/8/2000     1.24    Phil "Bryce" Copeland <copeland@redhat.com>
**                      Added Wensong's patches
**                      changed log() to piranha_log()
**
** 2/16/2000    1.25    Keith Barrett <kbarrett@redhat.com>
**                      Added send/expect arguments to nanny
**
** 2/18/2000    1.26 -  Keith Barrett <kbarrett@redhat.com>
**              1.27    Added persistent netmask
**
** 2/25/2000    1.28    Keith Barrett <kbarrett@redhat.com>
**                      Correctly pass on routing method switches
**                      Increased size of argv[]
**                      Correctly pass on protocol value
**
** 2/25/2000    1.29    Phil "Bryce" Copeland <copeland@redhat.com>
**                      (const) on argv
**
** 2/29/2000    1.30 -  Keith Barrett <kbarrett@redhat.com>
**              1.36    Resolved diffs in cvs
**                      Added call to lvsRelocate FS()
**                      Added typecasts to make strict compiles happier
**                      Fixed passing of switches to ipvsadm
**
** 3/1/2000     1.27    Keith Barrett <kbarrett@redhat.com>
**                      Moved FLAGS to util.h
**
** 7/13/2000    1.28    Keith Barrett <kbarrett@redhat.com>
**                      Changed "i" to "err" in startServices, according
**                      to patch provided by Flavio Pescuma. Also
**                      fixed missing arg in piranha_log() call.
**
** 7/20/2000	1.29	Keith Barrett <kbarrett@redhat.com>
**		1.30	Pass udp switch to nanny. Added --version.
**		        Added Bryce's CFGFILE logic.
**
** 8/1/2000	1.31	Keith Barrett <kbarrett@redhat.com>
**		        Added -v.
**
** 8/16/2000	1.32	Keith Moore <keith.moore@renp.com>
**		        Fix memory usage of persistence timeout parameter
**
** 9/11/2000	1.33	Philip Copeland <copeland@redhat.com>
**		        made least connections change from pcc -> lc
**
** 10/17/2000	1.34	Philip Copeland <bryce@redhat.com>
**		        Added some extra info to the --version option
**
** 6/15/2001	1.35	Philip Copeland <bryce@redhat.com>
**			Quick globals.h replacement
**
** 8/27/2001	1.36	Philip Copeland <bryce@redhat.com>
**			Merged in Wensongs fwmarks patch
**
** 9/22/2001	1.37	Philip Copeland <bryce@redhat.com>
**			Added in the send_program (-e) option
**
** 1/18/2002	1.38	Philip Copeland <bryce@redhat.com>
**			Added in pzb's patch
**			Later fixed up pzb's patch which forgot about lvs.c 
**
** 16/10/2002           Mike McLean <mikem@redhat.com>
**                      Passing --regex to nanny when useRegex is in effect
**
** 19-Jan 2004		Lon Hohberger <lhh@redhat.com>
**			Rename lvs.c -> lvscontrol.c to prevent naming 
**			collision with lvm2 stuff.
**
*/

/*
**  NOTE:   This program will break fail if it encounters a failover service
**          structure in the virtual servers list because it does not check.
**          This condition should not be possible under normal use because
**          relocateFailoverServices() is called.
*/


#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <popt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signal.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <assert.h>
#include <syslog.h>

#include "globals.h"
#include "lvsconfig.h"
#include "util.h"
#include "nanny.h"

#define _PROGRAM_VERSION LVS	/* From globals.h */

#define _(a) (a)
#define N_(a) (a)

/* Globals icky :-( */
static int termSignal = 0;
static int rereadFiles = 0;
static int debug_mode = 0;

struct clientInfo
{
  struct lvsVirtualServer *vserver;
  struct in_addr vip;
  struct in_addr address;
  int port, rport, protocol;
  int clientPipe;
  int clientActive;
  pid_t clientMonitor;		/* -1 if died */
};


int
shutdownDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	     struct in_addr *remoteAddr, int service_type, int fm, int udp);

int
bringUpDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	    struct in_addr *remoteAddr, char *routingMethod, int weight,
	    int service_type, int fm, int udp);

char *
rm_to_str(int redirectType) {
  switch (redirectType)
    {
    case LVS_REDIRECT_NAT:
      return (char *) "-m";
    case LVS_REDIRECT_DIRECT:
      return (char *) "-g";
    case LVS_REDIRECT_TUNNEL:
      return (char *) "-i";
    }
   return NULL;
}


/* returns 0 if clients match, 1 otherwise */

int cmpRealServers(struct clientInfo *client1, struct clientInfo *client2)
{
  if (memcmp(&client1->vip, &client2->vip, sizeof(client2->vip)))
    return 1;
  if (memcmp(&client1->address, &client2->address, sizeof(client2->address)))
    return 1;
  if (client1->port != client2->port)
    return 1;
  if (client1->rport != client2->rport)
    return 1;
  if (client1->protocol != client2->protocol)
    return 1;

  return 0;
}




static void
handleChildDeath (int signal)
{
  /* We don't need to do anything here as we always check for dead
     children when we get a signal. */
}




static void
handleTermSignal (int signal)
{
  termSignal = signal;
}




static void
handleHupSignal (int signal)
{
  rereadFiles = 1;
}


static void
handleAlarmSignal (int signal)
{
	/* nothing */
}


int
execArgv (int flags, char **argv)
{
  pid_t child;
  int status;

  logArgv (flags, argv);

  if (!(child = fork ()))
    {
      if (flags & LVS_FLAG_TESTSTARTS)
	exit (0);
      execv (argv[0], argv);
      exit (1);
    }

  waitpid (child, &status, 0);

  if (!WIFEXITED (status) || WEXITSTATUS (status))
    {
      return 1;
    }

  return 0;
}




/* returns -1 on no match */

int
findClientInList (struct clientInfo *clients, int numClients,
		  struct clientInfo *needle)
{

  int i;

  for (i = 0; i < numClients; i++)
    {
      if (cmpRealServers(&clients[i], needle))
        continue;
      return i;
    }

  return -1;
}




int
findClientConfig (struct lvsConfig *config, int *vserver, int *service,
		  struct clientInfo *needle)
{

  int vsn, sn;

  for (vsn = 0; vsn < config->numVirtServers; vsn++)
    {

      for (sn = 0; sn < config->virtServers[vsn].numServers; sn++)
	{
	  
	  struct clientInfo tinfo;
	  tinfo.vip = config->virtServers[vsn].virtualAddress;
	  tinfo.address = config->virtServers[vsn].servers[sn].address;
	  tinfo.protocol = config->virtServers[vsn].protocol;
	  tinfo.port = config->virtServers[vsn].servers[sn].port;
	  
	  if (cmpRealServers(&tinfo, needle))
	    continue;

	  *vserver = vsn;
	  *service = sn;
	  return 0;
	}
    }

  return -1;
}



char *
strip_quotes (char *in_string)
{
  char *tmp_ptr;
  char *out_string = NULL;

  if (in_string)
    {
      out_string = in_string;

      if (*in_string == '\"')
	{
	  ++out_string;
	}

      if (strlen (out_string))
	{
	  tmp_ptr = strlen (out_string) + out_string - 1;
	  if (*tmp_ptr == '\"')
	    *tmp_ptr = 0;
	}
    }

  return out_string;
}


/* This assumes there is enough room for all of the servers we need to
   start! It doesn't start up clients which are already running */

int
startClientMonitor (struct lvsConfig *config,
		    struct lvsVirtualServer *vserver,
		    struct lvsService *service,
		    struct clientInfo *clients, int *numClients, int flags)
{

  struct clientInfo clientInfo;
  int rc, cld_pipe[2] = {-1, -1}, cfl, have_sorry;
  char *realAddress;
  char *virtAddress;
  char *argv[42];
  char **arg = argv;
  char portNum[20], rportNum[20], timeoutNum[20], weightNum[20], reentryNum[20];
  char fwmNum[20];
  char buf[64];
  pid_t child;

  if (!service->isActive)
    return 0;

  memset(buf, 0, sizeof(buf));
  have_sorry = memcmp(&(vserver->sorry_server), buf,
		      sizeof(vserver->sorry_server));

  /* assume we're alive */
  vserver->runstate = 1;
  clientInfo.vserver = vserver;
  clientInfo.vip = vserver->virtualAddress;
  clientInfo.address = service->address;
  clientInfo.protocol = vserver->protocol;
  clientInfo.port = vserver->port;
  clientInfo.rport = service->port;

  rc = findClientInList (clients, *numClients, &clientInfo);

  if (rc != -1)
    return 0;

  virtAddress = strdup (inet_ntoa (vserver->virtualAddress));
  realAddress = strdup (inet_ntoa (service->address));

  sprintf (portNum, "%d", vserver->port);
  sprintf (rportNum, "%d", service->port);
  sprintf (timeoutNum, "%d", vserver->timeout);
  sprintf (weightNum, "%d", service->weight);
  sprintf (reentryNum, "%d", vserver->reentryTime);

  *arg++ = vserver->clientMonitor;
  *arg++ = (char *) "-c";
  *arg++ = (char *) "-h";
  *arg++ = realAddress;
  *arg++ = (char *) "-p";
  *arg++ = portNum;
  *arg++ = (char *) "-r";
  *arg++ = rportNum;

  if (vserver->fwmark)
    {
      sprintf (fwmNum, "%d", vserver->fwmark);
      *arg++ = (char *) "-f";
      *arg++ = fwmNum;
    }

  if (vserver->protocol == IPPROTO_UDP)
    *arg++ = (char *) "-u";
  /* UDP */

  if (vserver->send_program)
    {
      *arg++ = (char *) "-e";
      *arg++ = strip_quotes (vserver->send_program);
    }

  if (vserver->send_str)
    {
      *arg++ = (char *) "-s";
      *arg++ = strip_quotes (vserver->send_str);
    }

  if (vserver->expect_str)
    {
      *arg++ = (char *) "-x";
      *arg++ = strip_quotes (vserver->expect_str);
    }

  if (vserver->quiesceServer)
    *arg++ = (char *) "-q";

  if (vserver->useRegex)
    *arg++ = (char *) "--regex";

  if (debug_mode)
    *arg++ = (char *) "-v";	/* Pass along debug mode */

  *arg++ = (char *) "-a";
  *arg++ = reentryNum;
  *arg++ = (char *) "-I";
  *arg++ = config->vsadm;
  *arg++ = (char *) "-t";
  *arg++ = timeoutNum;
  *arg++ = (char *) "-w";
  *arg++ = weightNum;
  *arg++ = (char *) "-V";
  *arg++ = virtAddress;
  *arg++ = (char *) "-M";

  switch (config->redirectType)
    {

    case LVS_REDIRECT_NAT:
      *arg++ = (char *) "m";
      break;

    case LVS_REDIRECT_DIRECT:
      *arg++ = (char *) "g";
      break;

    case LVS_REDIRECT_TUNNEL:
      *arg++ = (char *) "i";
      break;

    case LVS_REDIRECT_UNKNOWN:
      abort ();
    }

  if (vserver->loadMonitor)
    {
    *arg++ = (char *) "-U";
    if (strcmp (vserver->loadMonitor, "uptime"))
        *arg++ = vserver->loadMonitor;
    else
        *arg++ = config->rshCommand;
    }
    
  /* send this to nanny if we don't have a sorry server */
  if (!(flags & LVS_FLAG_ASDAEMON) || have_sorry)
    {
      *arg++ = (char *) "--nodaemon";	/* Pass along --nodaemon */
    }

  /* ah,.. nanny will expect to be told if this is a lvs or a fos mission */
  /* Lets just scribble in the --lvs bit and we'll be on our way */
  
  *arg++ = (char *) "--lvs";
  	          
  /* Terminate the command line call */
  
  *arg++ = NULL;

  logArgv (flags, argv);

  if (!(flags & LVS_FLAG_TESTSTARTS))
    {
      if (have_sorry && pipe(cld_pipe) < 0) {
        /* do exactly what here? */
	assert(0);
      }

      child = fork ();

      if (!child)
	{
	  prctl (PR_SET_PDEATHSIG, SIGTERM);

	  /* Smoke a pipe, yo */
	  if (have_sorry) {
	    dup2(cld_pipe[0], STDIN_FILENO);
	    dup2(cld_pipe[1], STDOUT_FILENO);
	    dup2(cld_pipe[1], STDERR_FILENO);

	    if (cld_pipe[0] > 2)
		close(cld_pipe[0]);
	    if (cld_pipe[1] > 2)
	  	close(cld_pipe[1]);

	    /* Don't block on writes.  Or anything. */
	    cfl = fcntl(STDIN_FILENO, F_GETFL);
	    fcntl(STDIN_FILENO, F_SETFL, cfl | O_NONBLOCK);
	    cfl = fcntl(STDOUT_FILENO, F_GETFL);
	    fcntl(STDOUT_FILENO, F_SETFL, cfl | O_NONBLOCK);
	    cfl = fcntl(STDERR_FILENO, F_GETFL);
	    fcntl(STDERR_FILENO, F_SETFL, cfl | O_NONBLOCK);
	  }

	  execv (argv[0], argv);
	  exit (1);
	}

      /* don't need this half of it */
      /* nonblocking I/o */
      if (have_sorry) {
        close(cld_pipe[1]);
        cfl = fcntl(cld_pipe[0], F_GETFL);
        fcntl(cld_pipe[0], F_SETFL, cfl | O_NONBLOCK);
      }
      piranha_log (flags,
		   (char *) "create_monitor for %s/%s running as pid %d",
		   vserver->name, service->name, child);

    }
  else
    {
      child = -1;
    }

  free (virtAddress);
  free (realAddress);

  clientInfo.vserver = vserver;
  clientInfo.clientMonitor = child;
  clientInfo.clientPipe = cld_pipe[0];
  clientInfo.clientActive = 0;
  clients[*numClients] = clientInfo;
  (*numClients)++;

  return 0;
}


int
shutdownClientMonitor (struct lvsConfig *config,
		       struct lvsVirtualServer *vserver,
		       struct lvsService *service,
		       struct clientInfo *clients,
		       int *numClientsPtr, int flags)
{

  int which;
  struct clientInfo clientInfo;

  clientInfo.vip = vserver->virtualAddress;
  clientInfo.address = service->address;
  clientInfo.protocol = vserver->protocol;
  clientInfo.port = vserver->port;
  clientInfo.rport = service->port;


  which = findClientInList (clients, *numClientsPtr, &clientInfo);

  if (which == -1)
    return 0;


  if (clients[which].clientMonitor != -1)
    {
      kill (clients[which].clientMonitor, SIGTERM);
      waitpid (clients[which].clientMonitor, NULL, 0);
      clients[which].vserver = NULL;
      clients[which].clientActive = 0;
      close(clients[which].clientPipe);
      clients[which].clientPipe = -1;
    }

  if (which != (*numClientsPtr - 1))
    clients[which] = clients[*numClientsPtr - 1];

  (*numClientsPtr)--;
  return 0;
}




int
shutdownVirtualServer (struct lvsConfig *config,
		       struct lvsVirtualServer *vserver,
		       int flags,
		       struct clientInfo *clients, int *numClientsPtr)
{

  char *argv[42];
  char **arg = argv;
  char virtAddress[50];
  char fwmNum[20];
  int i;

  if (!vserver->isActive)
    return 0;

  piranha_log (flags,
	       (char *) "shutting down virtual service %s", vserver->name);

  *arg++ = config->vsadm;
  *arg++ = (char *) "-D";

  if (vserver->fwmark)
    {
      *arg++ = (char *) "-f";
      (void) sprintf (fwmNum, "%d", vserver->fwmark);
      *arg++ = fwmNum;
    }
  else
    {
      switch (vserver->protocol)
	{
	case IPPROTO_UDP:
	  *arg++ = (char *) "-u";
	  break;

	case IPPROTO_TCP:
	default:
	  *arg++ = (char *) "-t";
	  break;
	}
      sprintf (virtAddress, "%s:%d", inet_ntoa (vserver->virtualAddress),
	       vserver->port);
      *arg++ = virtAddress;
    }

  *arg++ = NULL;

  for (i = 0; i < vserver->numServers; i++)
    shutdownClientMonitor (config, vserver, vserver->servers + i,
			   clients, numClientsPtr, flags);

  if (execArgv (flags, argv))
    {
      piranha_log (flags, (char *) "ipvsadm failed for virtual server %s!",
		   vserver->name);
      return 1;
    }

  return 0;
}





/* This assumes there is enough room for all of the servers we need to
   start! */

int
startVirtualServer (struct lvsConfig *config,
		    struct lvsVirtualServer *vserver,
		    int flags, struct clientInfo *clients, int *numClientsPtr)
{
  int i;
  char *argv[40];
  char wrkBuf[10];
  char fwmNum[20];
  char **arg = argv;
  char virtAddress[50];
  int oldNumClients;
  char *pmask = NULL;

  if (!vserver->isActive)
    return 0;

  piranha_log (flags, (char *) "starting virtual service %s active: %d",
	       vserver->name, vserver->port);

  *arg++ = config->vsadm;
  *arg++ = (char *) "-A";

  if (vserver->fwmark)
    {
      *arg++ = (char *) "-f";
      (void) sprintf (fwmNum, "%d", vserver->fwmark);
      *arg++ = fwmNum;
    }
  else
    {
      switch (vserver->protocol)
	{
	case IPPROTO_UDP:
	  *arg++ = (char *) "-u";
	  break;

	case IPPROTO_TCP:
	default:
	  *arg++ = (char *) "-t";
	  break;
	}
      sprintf (virtAddress, "%s:%d", inet_ntoa (vserver->virtualAddress),
	       vserver->port);
      *arg++ = virtAddress;
    }

  *arg++ = (char *) "-s";

  switch (vserver->scheduler)
    {
    case LVS_SCHED_LC:
      *arg++ = (char *) "lc";
      break;

    case LVS_SCHED_WLC:
      *arg++ = (char *) "wlc";
      break;

    case LVS_SCHED_RR:
      *arg++ = (char *) "rr";
      break;

    case LVS_SCHED_WRR:
      *arg++ = (char *) "wrr";
      break;

    case LVS_SCHED_LBLC:
      *arg++ = (char *) "lblc";
      break;

    case LVS_SCHED_LBLCR:
      *arg++ = (char *) "lblcr";
      break;

    case LVS_SCHED_DH:
      *arg++ = (char *) "dh";
      break;

    case LVS_SCHED_SH:
      *arg++ = (char *) "sh";
      break;

    default:
      abort ();
    }


  if (vserver->persistent > 0)
    {
      *arg++ = (char *) "-p";
      (void) sprintf (wrkBuf, "%d", vserver->persistent);
      *arg++ = wrkBuf;

      if (vserver->pmask.s_addr)
	{
	  pmask = inet_ntoa (vserver->pmask);

	  if (pmask)
	    {
	      *arg++ = (char *) "-M";
	      *arg++ = pmask;
	    }
	}
    }

  *arg++ = NULL;

  if (execArgv (flags, argv))
    {
      piranha_log (flags, (char *) "ipvsadm failed for virtual server %s!",
		   vserver->name);
      return 1;
    }

  oldNumClients = *numClientsPtr;

  for (i = 0; i < vserver->numServers; i++)
    {
      startClientMonitor (config, vserver, vserver->servers + i,
			  clients, numClientsPtr, flags);
    }

  return 0;
}






int
restartVirtualServer (struct lvsConfig *config,
		      struct lvsVirtualServer *oldVserver,
		      struct lvsVirtualServer *vserver,
		      int flags,
		      struct clientInfo *clients, int *numClientsPtr)
{

  int old, new;
  enum
  { WHAT_UNKNOWN, WHAT_START, WHAT_STOP, WHAT_SKIP }
  what;


  /* look for old servers which no longer exist */

  for (old = 0; old < oldVserver->numServers; old++)
    {

      for (new = 0; new < vserver->numServers; new++)
	{

	  if (memcmp (&oldVserver->servers[old].address,
		      &vserver->servers[new].address,
		      sizeof (vserver->servers[new].address)))
	    continue;

	  if (oldVserver->servers[old].port != vserver->servers[new].port)
	    continue;

	  break;
	}

      if ((new == vserver->numServers) && (vserver->numServers != 0))
	{			/* This service is gone. */
	  shutdownVirtualServer (config, oldVserver, flags, clients,
				 numClientsPtr);
	}
    }


  /* Start/stop client monitors as appropriate */

  for (new = 0; new < vserver->numServers; new++)
    {

      for (old = 0; old < oldVserver->numServers; old++)
	{

	  if (memcmp (&oldVserver->servers[old].address,
		      &vserver->servers[new].address,
		      sizeof (vserver->servers[new].address)))
	    continue;

	  if (oldVserver->servers[old].port != vserver->servers[new].port)
	    continue;

	  break;
	}

      what = WHAT_UNKNOWN;

      if (old == oldVserver->numServers)
	{			/* new service */
	  what = WHAT_START;

	}
      else if (oldVserver->servers[old].isActive &&
	       vserver->servers[new].isActive)
	{
	  /* old active, new active */
	  what = WHAT_SKIP;

	}
      else if (!oldVserver->servers[old].isActive &&
	       !vserver->servers[new].isActive)
	{
	  /* old not active, new not active */
	  what = WHAT_STOP;

	}
      else if (oldVserver->servers[old].isActive &&
	       !vserver->servers[new].isActive)
	{
	  /* old active, new not active */
	  what = WHAT_STOP;

	}
      else if (!oldVserver->servers[old].isActive &&
	       vserver->servers[new].isActive)
	{
	  /* old not active, new active */
	  what = WHAT_START;
	}

      if (what == WHAT_START)
	startClientMonitor (config, vserver, vserver->servers + new,
			    clients, numClientsPtr, flags);

      else if (what == WHAT_STOP)
	shutdownClientMonitor (config, vserver, vserver->servers + new,
			       clients, numClientsPtr, flags);
    }

  return 0;
}





int
setTimeouts (struct lvsConfig *config, int flags)
{
  char *argv[40];
  char **arg = argv;
  char tcpTimeout[20];
  char tcpfinTimeout[20];
  char udpTimeout[20];

  sprintf (tcpTimeout, "%d", config->tcpTimeout);
  sprintf (tcpfinTimeout, "%d", config->tcpfinTimeout);
  sprintf (udpTimeout, "%d", config->udpTimeout);

  *arg++ = config->vsadm;
  *arg++ = (char *) "--set";
  *arg++ = tcpTimeout;
  *arg++ = tcpfinTimeout;
  *arg++ = udpTimeout;
  *arg++ = NULL;

  if (execArgv (flags, argv))
    {
      piranha_log (flags, (char *)
		   "ipvsadm failed to set timeouts (%s %s %s)",
		   tcpTimeout, tcpfinTimeout, udpTimeout);
      return 1;
    }

  return 0;
}






int
rereadConfigFiles (struct lvsConfig *oldConfig,
		   struct clientInfo **clientsPtr,
		   int *numClientsPtr,
		   int *numClientsAllocedPtr,
		   const char *configFile, int flags)
{

  struct lvsConfig newConfig;
  int fd;
  int i, j;
  int size;
  int rc;
  int line;

  enum
  { WHAT_UNKNOWN, WHAT_START, WHAT_STOP, WHAT_RESTART,
    WHAT_SKIP
  }
  what;


  if ((fd = open (configFile, O_RDONLY)) < 0)
    {
      piranha_log (flags, (char *) "lvs: failed to open %s", configFile);
      return 1;
    }

  if ((rc = lvsParseConfig (fd, &newConfig, &line)))
    {
      piranha_log (flags, (char *) "lvs: error parsing %s on line %d.\n",
		   configFile, line);
      return 1;
    }

  close(fd);

  lvsRelocateFS (&newConfig);
  /* Move failover services to own list and clean up virtual server list */

  if ((oldConfig->tcpTimeout != newConfig.tcpTimeout) ||
      (oldConfig->tcpfinTimeout != newConfig.tcpfinTimeout) ||
      (oldConfig->udpTimeout != newConfig.udpTimeout))
  {
      setTimeouts (&newConfig, flags);
  }

  for (i = 0; i < oldConfig->numVirtServers; i++)
    {

      for (j = 0; j < newConfig.numVirtServers; j++)
	{

	  if (!memcmp (&oldConfig->virtServers[i].virtualAddress,
		       &newConfig.virtServers[j].virtualAddress,
		       sizeof (newConfig.virtServers[j].virtualAddress)) &&
	      (oldConfig->virtServers[i].protocol ==
	       newConfig.virtServers[j].protocol) &&
	      (oldConfig->virtServers[i].port ==
	       newConfig.virtServers[j].port))
	    break;
	}

      if (j == newConfig.numVirtServers)
	{
	  /* This server no longer exists -- kill it */
	  shutdownVirtualServer (oldConfig, oldConfig->virtServers + i,
				 flags, *clientsPtr, numClientsPtr);
	}
    }


  /* Now restart all of the virtual servers which still exist (or are new).
     Note that servers whose active states have changed need to be handled
     here as well. */

  for (i = 0; i < newConfig.numVirtServers; i++)
    {

      for (j = 0; j < oldConfig->numVirtServers; j++)
	{

	  if (!memcmp (&oldConfig->virtServers[j].virtualAddress,
		       &newConfig.virtServers[i].virtualAddress,
		       sizeof (newConfig.virtServers[i].virtualAddress)) &&
	      (oldConfig->virtServers[j].protocol ==
	       newConfig.virtServers[i].protocol) &&
	      (oldConfig->virtServers[j].port ==
	       newConfig.virtServers[i].port))
	    break;
	}

      what = WHAT_UNKNOWN;

      if (j == oldConfig->numVirtServers)
	/* New server! That's easy. */
	what = WHAT_START;

      else if (newConfig.virtServers[i].isActive &&
	       oldConfig->virtServers[j].isActive)
	/* New active, old active */
	what = WHAT_RESTART;

      else if (!newConfig.virtServers[i].isActive &&
	       !oldConfig->virtServers[j].isActive)
	/* New not active, old not active */
	what = WHAT_SKIP;

      else if (newConfig.virtServers[i].isActive &&
	       !oldConfig->virtServers[j].isActive)
	/* New active, old not active */
	what = WHAT_START;

      else if (!newConfig.virtServers[i].isActive &&
	       oldConfig->virtServers[j].isActive)
	/* New not active, old active */
	what = WHAT_STOP;


      if (what == WHAT_STOP)
	{
	  shutdownVirtualServer (oldConfig, oldConfig->virtServers + j,
				 flags, *clientsPtr, numClientsPtr);
	}
      else
	{
	  size = *numClientsPtr + newConfig.virtServers[i].numServers;
	  *clientsPtr = realloc (*clientsPtr, sizeof (**clientsPtr) * size);

	  if (what == WHAT_START)
	    startVirtualServer (&newConfig, newConfig.virtServers + i,
				flags, *clientsPtr, numClientsPtr);
	  else if (what == WHAT_RESTART)
	    restartVirtualServer (&newConfig, oldConfig->virtServers + j,
				  newConfig.virtServers + j, flags,
				  *clientsPtr, numClientsPtr);
	}
    }

  lvsFreeConfig(oldConfig);
  *oldConfig = newConfig;
  return 0;
}

int
activeClientCount(struct lvsVirtualServer *vs, struct clientInfo *clients,
		  int numClients)
{
  int count = 0, i;

  for (i = 0; i < numClients; i++) {
    if (clients[i].vserver == vs && clients[i].clientActive)
      count++;
  }

  return count;
}


void
updateClientStatus(struct clientInfo *client)
{
  char buf[80];
  int n;

  memset(buf, 0, sizeof(buf));
  while ((n = read(client->clientPipe, buf, sizeof(buf))) >= 0) {
    if (n >= NANNY_STATUS_SIZE) {
      if (strstr(buf, NANNY_ACTIVE_STATUS) && !client->clientActive) {
        //fprintf(stderr, "nanny pid %d activated\n", client->clientMonitor );
        client->clientActive = 1;
      } else if (strstr(buf, NANNY_INACTIVE_STATUS) && client->clientActive) {
        //fprintf(stderr, "nanny pid %d inactive\n", client->clientMonitor );
        client->clientActive = 0;
      }
    }

    if (n == 0)
      break;
  }
}


int
checkClientMonitor(struct lvsConfig *config, struct lvsVirtualServer *vs,
		   struct clientInfo *clients,
		   int numClients, int flags)
{
  fd_set rfds;
  int max = -1, i, have_sorry;
  int nready = 0;
  struct timeval tv = {0, 0};
  char buf[64];

  /* XXX */
  assert(sizeof(buf) > sizeof(config->virtServers[i].sorry_server) );

  /* This is a no-op if we don't have a sorry_server */
  memset(buf, 0, sizeof(buf));
  have_sorry = memcmp(&(vs->sorry_server), buf,
		sizeof(vs->sorry_server));
  if (!have_sorry)
      return 0;

  /* We've got a sorry server - run our list looking for clients */
  /* Find all clientPipes ... */
  FD_ZERO(&rfds);
  for (i = 0; i < numClients; i++) {
    if (clients[i].vserver == vs && clients[i].clientPipe >= 0) { 
      FD_SET(clients[i].clientPipe, &rfds);
      if (clients[i].clientPipe > max)
        max = clients[i].clientPipe;
    }
  }

  nready = select(max + 1, &rfds, NULL, NULL, &tv);
  if (nready < 0) {
    piranha_log (flags,
	         (char *) "select(): %s", strerror(errno));
    return -1;
  } else if (nready > 0) {

    /* Ok, update our status... thingies. */
    for (i = 0; i < numClients; i++) {
      if (clients[i].vserver == vs &&
          FD_ISSET(clients[i].clientPipe,&rfds)) {
        
	FD_CLR(clients[i].clientPipe, &rfds);
        updateClientStatus(&clients[i]);
      }
    }
  }

  /* count active clients and see if we need to activate the
     sorry_server */
  max = activeClientCount(vs, clients, numClients);

  if (!max && vs->runstate) {
    vs->runstate = 0;

    inet_ntop(AF_INET, &vs->sorry_server, buf, sizeof(buf));
    printf("Virtual Server %s: No real servers; activate sorry_server %s\n",
	   vs->name, buf);
    inet_ntop(AF_INET, &vs->virtualAddress, buf, sizeof(buf));
    bringUpDev(flags,
	       config->vsadm,
	       buf, vs->port,
	       &vs->sorry_server,
	       rm_to_str(config->redirectType),
	       1, SERV_LVS,
	       vs->fwmark, (vs->protocol == IPPROTO_UDP));


  } else if (max && !vs->runstate) {
    vs->runstate = 1;

    inet_ntop(AF_INET, &vs->sorry_server, buf, sizeof(buf));
    printf("Virtual Server %s: %d real servers; deactivate sorry_server %s\n",
	   vs->name, max, buf);
    inet_ntop(AF_INET, &vs->virtualAddress, buf, sizeof(buf));
    shutdownDev(flags,
	        config->vsadm,
	        buf, vs->port,
	        &vs->sorry_server,
	        SERV_LVS,
	        vs->fwmark, (vs->protocol == IPPROTO_UDP));
  }

  return 0;
}


int
checkClientMonitors(struct lvsConfig *config, struct clientInfo *clients,
		    int numClients, int flags)
{
  int i, ret = 0;

  for (i = 0; i < config->numVirtServers; i++) {
    ret += checkClientMonitor(config, &config->virtServers[i], clients,
			      numClients, flags);
  }

  return ret;
}


int
startServices (struct lvsConfig *config, int flags, char *configFile)
{

  int i, err;
  struct clientInfo *clients = NULL;
  int numClients = 0, numClientsAlloced = 0;
  sigset_t sigs;
  pid_t pid;
  int status;
  int doShutdown = 0;
  int vsn, sn;

  if (flags & LVS_FLAG_ASDAEMON)
    {
      flags |= LVS_FLAG_SYSLOG;

      if (daemonize (flags))
	return 0;
    }

  if (flags & LVS_FLAG_SYSLOG)
    {
      openlog ("lvsd", LOG_PID, LOG_DAEMON);
    }

  sigemptyset (&sigs);
  sigaddset (&sigs, SIGINT);
  sigaddset (&sigs, SIGCHLD);
  sigaddset (&sigs, SIGTERM);
  sigaddset (&sigs, SIGHUP);
  sigprocmask (SIG_BLOCK, &sigs, NULL);

  signal (SIGCHLD, handleChildDeath);
  signal (SIGINT, handleTermSignal);
  signal (SIGTERM, handleTermSignal);
  signal (SIGHUP, handleHupSignal);
  signal (SIGALRM, handleAlarmSignal);

  for (i = 0; i < config->numVirtServers; i++)
    {
      if ((numClients + config->virtServers[i].numServers) >=
	  numClientsAlloced)
	{
	  numClientsAlloced = numClients + config->virtServers[i].numServers;
	  clients = realloc (clients, sizeof (*clients) * numClientsAlloced);
	}

      startVirtualServer (config, config->virtServers + i, flags, clients,
			  &numClients);
    }

  sigfillset (&sigs);
  sigdelset (&sigs, SIGALRM);
  sigdelset (&sigs, SIGINT);
  sigdelset (&sigs, SIGCHLD);
  sigdelset (&sigs, SIGTERM);
  sigdelset (&sigs, SIGHUP);


  while (!doShutdown)
    {
      alarm(5);
      sigsuspend (&sigs);
      alarm(0);

      while ((pid = waitpid (-1, &status, WNOHANG)) > 0)
	{
	  for (i = 0; i < numClients; i++)
	    {
	      if (clients[i].clientMonitor == pid)
		break;
	    }

	  if (i < numClients)
	    {
	      err = findClientConfig (config, &vsn, &sn, clients + i);
	      if (err) {
		piranha_log (flags,
			     (char *)
			     "nanny died! shutting down lvs");
                doShutdown = 1;
	      } else {
                if (config->hardShutdown) {
  		  piranha_log (flags,
			     (char *)
			     "nanny for child %s/%s died! shutting down lvs",
			     config->virtServers[vsn].name,
			     config->virtServers[vsn].servers[sn].name);
                  doShutdown = 1;
                } else {
  		  piranha_log (flags,
			     (char *)
			     "nanny for child %s/%s died! manual action needed!",
			     config->virtServers[vsn].name,
			     config->virtServers[vsn].servers[sn].name);                
                }
	      }

	      /* Clean up client pipes */
	      clients[i].clientMonitor = -1;
	      clients[i].clientActive = 0;
	      close(clients[i].clientPipe);
	      clients[i].clientPipe = -1;
	    }
	}

      checkClientMonitors(config, clients, numClients, flags);

      if (termSignal)
	{
	  piranha_log (flags,
		       (char *) "shutting down due to signal %d", termSignal);
	  doShutdown = 1;
	}

      if (rereadFiles)
	{
	  piranha_log (flags, (char *) "rereading configuration file");
	  rereadConfigFiles (config, &clients, &numClients,
			     &numClientsAlloced, configFile, flags);
	  rereadFiles = 0;
	}
    }


  for (i = 0; i < config->numVirtServers; i++)
    {
      shutdownVirtualServer (config, config->virtServers + i, flags,
			     clients, &numClients);
    }

  if (flags & LVS_FLAG_ASDAEMON)
    unlink ("/var/run/lvs.pid");

  return 0;
}





int
clearVcsTable (struct lvsConfig *config, int flags)
{
  char *argv[40];
  char **arg = argv;

  *arg++ = config->vsadm;
  *arg++ = (char *) "-C";
  *arg++ = NULL;

  execArgv (flags, argv);
  return 0;
}





int
main (int argc, const char **argv)
{

  char *configFile = (char *) CFGFILE;	/* Supplied by globals.h */
  int testStart = 0, noDaemon = 0;
  poptContext optCon;
  int rc, flags = 0, fd, line;
  int noFork = 0;
  struct lvsConfig config;
  int display_ver = 0;

  struct poptOption options[] = {
    {"configfile", 'c', POPT_ARG_STRING, &configFile, 0,
     N_("Configuration file"), N_("configfile")},

    {"verbose", 'v', 0, &debug_mode, 0,
     N_("Verbose (debug) output")},

    {"nodaemon", 'n', 0, &noDaemon, 0,
     N_("Don't run as a daemon")},

    {"test-start", 't', 0, &testStart, 0,
     N_("Display what commands would be run on startup, but "
	"don't actually run anything")},

    {"nofork", '\0', 0, &noFork, 0,
     N_("Don't fork, but do disassociate")},

    {"version", '\0', 0, &display_ver, 0,
     N_("Display program version")},

    POPT_AUTOHELP {0, 0, 0, 0, 0}
  };

  optCon = poptGetContext ("lvs", argc, argv, options, 0);
  poptReadDefaultConfig (optCon, 1);

  if ((rc = poptGetNextOpt (optCon)) < -1)
    {
      fprintf (stderr, _("lvs: bad argument %s: %s\n"),
	       poptBadOption (optCon, POPT_BADOPTION_NOALIAS),
	       poptStrerror (rc));
      return 1;
    }

  if (poptGetArg (optCon))
    {
      fprintf (stderr, _("lvs: unexpected arguments\n"));
      return 1;
    }

  poptFreeContext (optCon);
  logName ((char *) "lvs");
  flags = 0;

  if (display_ver)
    {
      printf ("Program Version:\t%s\n", _PROGRAM_VERSION);
      printf ("Built:\t\t\t%s\n", DATE);	/* DATE pulled from Makefile */
      printf ("A component of:\t\tpiranha-%s-%s\n", VERSION, RELEASE);
      return 0;
    }

  if (testStart)
    flags |= LVS_FLAG_TESTSTARTS;

  if (!noDaemon)
    flags |= LVS_FLAG_ASDAEMON | LVS_FLAG_SYSLOG;
  else
    flags |= LVS_FLAG_PRINTF;

  if (noFork)
    {
      flags |= LVS_FLAG_NOFORK;
    }

  if ((fd = open (configFile, O_RDONLY)) < 0)
    {
      fprintf (stderr, "lvs: failed to open %s\n", configFile);
      return 1;
    }

  if ((rc = lvsParseConfig (fd, &config, &line)))
    {
      fprintf (stderr, "lvs: error parsing %s on line %d.\n", configFile,
	       line);
      return 1;
    }

  close (fd);

  lvsRelocateFS (&config);
  /* Move failover services to own list and clean up virtual server list */

  setTimeouts (&config, flags);
  clearVcsTable (&config, flags);
  return startServices (&config, flags, configFile);
}
