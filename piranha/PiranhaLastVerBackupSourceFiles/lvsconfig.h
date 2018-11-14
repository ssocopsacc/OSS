 /* Red Hat Clustering Tools 
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
    ** 9/xx/1999	1.0	Erik Troan <ewt@redhat.com>
    **			1.13	Original release and repairs.
    **
    ** 9/7/1999		1.14	Havoc Pennington <hp@redhat.com>
    **				Added name files & support for GUI.
    **
    ** 9/25/2000	1.15	Erik Troan <ewt@redhat.com>
    **				Added backup_active
    **
    ** 11/4/1999	1.16	Mike Wangsmo <wanger@redhat.com>
    **				Added persistence
    ** 
    ** 2/15/2000	1.17	Keith Barrett <kbarrett@redhat.com>
    **				Added support for send/expect strings
    **
    ** 2/18/2000	1.18	Keith Barrett <kbarrett@redhat.com>
    **				Added persistence netmask
    **
    ** 2/25/2000	1.19	Keith Barrett <kbarrett@redhat.com>
    **			1.21	Added failover services data elements
    **				Added prototype for lvsRelocateFS()
    **
    ** 3/2/2000		1.22	Keith Barrett <kbarrett@redhat.com>
    **				Added serviceType field
    **
    ** 09/11/2000	1.23	Philip Copeland <copeland@redhat.com>
    **				Fixed least connectiions 
    **				renamed LVS_SCHED_PCC to LVS_SCHED_LC
    **
    ** ??/??/2001	1.24	Philip Copeland <copeland@redhat.com>
    **				Added netmask fields
    **
    ** 05/31/2001	1.25	Keith Barrett <kbarrett@redhat.com>
    **				Removed netmask for main address
    **				Added netmask error code
    **				Removed ipchains element
    **
    ** 07/02/2001	1.26	Tim Waugh <twaugh@redhat.com>
    **				Heartbeat on dedicated interface
    **				Shared SCSI
    **
    ** 07/12/2001	1.27	Philip Copeland <copeland@redhat.com>
    **				Added lblc dh and sh sheduling options
    **
    ** 07/12/2001	1.28	Philip Copeland <copeland@redhat.com>
    **				add in definition to struct for the serial number
    **
    ** 09/25/2001	1.29	Philip Copeland <copeland@redhat.com>
    **				added in the send_program field to the
    **				lvsVirtualServer structure.
    **
    ** 16/10/2002               Mike McLean <mikem@redhat.com>
    **                          added the useRegex field to the
    **                          lvsVirtualServer struct
  */


#ifndef H_LVS_LVSCONFIG_H
#define H_LVS_LVSCONFIG_H

#include <arpa/inet.h>
#include <netinet/in.h>

enum lvsBackupMode
{ LVS_BACKUP_MODE_UNKNOWN = 0,
  LVS_BACKUP_MODE_BACKUP = 1, LVS_BACKUP_MODE_SWITCH = 2
};

enum lvsRedirectionType
{ LVS_REDIRECT_UNKNOWN = 0,
  LVS_REDIRECT_NAT, LVS_REDIRECT_DIRECT,
  LVS_REDIRECT_TUNNEL
};

enum lvsSchedulers
{
  LVS_SCHED_UNKNOWN = 0,
  LVS_SCHED_LC,
  LVS_SCHED_RR,
  LVS_SCHED_WLC,
  LVS_SCHED_WRR,
  LVS_SCHED_LBLC,
  LVS_SCHED_LBLCR,
  LVS_SCHED_DH,
  LVS_SCHED_SH
};

enum lvsServiceTypes
{ LVS_SERVICE_TYPE_LVS = 0, LVS_SERVICE_TYPE_FOS };

struct lvsService
{
  char *name;
  struct in_addr address;
/*  struct in_addr nmask;               Not used for real addresses */
  int isActive;
  int port;
  int weight;
  char *logFile;		/* NULL for stdout */
};

struct lvsVirtualServer
{
  char *name;
  int isActive;
  int runstate;
  char *virtualDevice;
  struct in_addr virtualAddress;	/* for Virtual IP address */
  struct in_addr vip_nmask;
  struct in_addr broadcast;
  struct in_addr sorry_server;

  unsigned int fwmark;		/* for fwmark-based virtual server */
  int protocol;			/* IPPROTO_TCP or IPPROTO_UDP */
  int port;
  enum lvsSchedulers scheduler;
  int persistent;
  struct in_addr pmask;

  char *clientMonitor;		/* client monitor progrm name & loc */
  char *send_program;
  char *send_str;
  char *expect_str;
  int timeout;
  int reentryTime;
  int quiesceServer;
  int useRegex;
  char *loadMonitor;

  char *start_cmd;		/* Only used by failover service */
  char *stop_cmd;		/* Only used by failover service */
  int failover_service;		/* != 0 means this is a failover service */
  struct in_addr masterServer;
  char **dirs;

  int numServers;
  struct lvsService *servers;
};

struct lvsConfig
{
  int serial_no;		/* Similar to DNS's serial no. scheme */
  struct in_addr primaryServer;
  char *primaryServerName;
  struct in_addr primaryPrivate;
  char *primaryPrivateName;
  char *primaryShared;
  struct in_addr backupServer;
  char *backupServerName;
  struct in_addr backupPrivate;
  char *backupPrivateName;
  char *backupShared;
  struct in_addr natRouter;
  struct in_addr nat_nmask;
  int backupActive;
  char *natRouterDevice;
  int useHeartbeat;
  int heartbeatPort;
  int keepAliveTime;
  int deadTime;
  int useFileSync;
  char *rshCommand;
  char *debug_level;
  char *vsadm;
  char *reserve;		/* SCSI reservation utility */
  enum lvsRedirectionType redirectType;
  enum lvsServiceTypes lvsServiceType;
  int numVirtServers;
  int numFailoverServices;
  struct lvsVirtualServer *virtServers;
  struct lvsVirtualServer *failoverServices;
  char *reservation_conflict_action;	/* "preempt" or "nothing" */
  int useSyncDaemon;
  int syncdID;
  char *syncdInterface;
  char *activeCommand;
  char *inactiveCommand;
  int monitorLinks; /* Check the link states before sending heartbeats,
		       only works with non-bonded interfaces */
  int hardShutdown;
  int tcpTimeout;
  int tcpfinTimeout;
  int udpTimeout;
};

int lvsParseConfig (int fd, struct lvsConfig *config, int *badLineNum);
const char *lvsStrerror (int rc);
void lvsInitVirtualServer (struct lvsVirtualServer *vs, const char *name);
void lvsRelocateFS (struct lvsConfig *config);

/* File descriptor and filename where final (merged) config file
   should be placed, config information to merge in, and pointer for
   line number in case an error occurs while parsing fd */

int lvsMergeConfig (int fd, int outfd,
		    struct lvsConfig *config, int *badLineNum);
void lvsFreeConfig (struct lvsConfig *config);

#define     LVS_ERROR_ERRNO          0x40000000
#define     LVS_ERROR_STAT           1 | LVS_ERROR_ERRNO
#define     LVS_ERROR_READ           2 | LVS_ERROR_ERRNO
#define     LVS_ERROR_BADQUOTING     3 | LVS_ERROR_ERRNO
#define     LVS_ERROR_EOF            4
#define     LVS_ERROR_EXTRAARGS      5
#define     LVS_ERROR_EQUALEXPECTED  6
#define     LVS_ERROR_MISSINGARGS    7
#define     LVS_ERROR_BADHOSTNAME    8
#define     LVS_ERROR_BADARGUMENT    9
#define     LVS_ERROR_INTEXPECTED    10
#define     LVS_ERROR_BOOLEXPECTED   11
#define     LVS_ERROR_BADCOMMAND     12
#define     LVS_ERROR_LISTEXPECTED   13
#define     LVS_ERROR_TOOMANYARGS    14
#define     LVS_ERROR_ONLYONESERVICE 15
#define     LVS_ERROR_BADNETMASK     16

#endif
