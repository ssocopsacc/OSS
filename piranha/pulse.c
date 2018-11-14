/*
 ** pulse.c -- detect lvs or fos failure
 **
 ** Red Hat Clustering Tools 
 ** Copyright 1999 Red Hat, Inc.
 **
 ** Author:  Erik Troan <ewt@redhat.com>
 **
 **
 ** You may freely redistributed or modified this file under the
 ** terms of the GNU General Public License; version 2 or (at your
 ** option), any later version.
 **
 ** You should have received a copy of the GNU General Public License
 ** along with this program; if not, write to the Free Software
 ** Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 **
 **
 ** MODIFICATION HISTORY:
 **
 ** 09/xx/1999   1.0 -   Erik Troan <ewt@redhat.com>
 **              1.9     Original release & repairs
 **
 ** 12/19/1999   1.10    Phil "Bryce" Copeland <copeland@redhat.com>
 **                      Minor typecasts and other changes for 64bit.
 **
 ** 01/08/2000   1.11    Phil "Bryce" Copeland <copeland@redhat.com>
 **                      Changed log() to piranha_log()
 ** 
 ** 01/28/2000   1.12 -  Keith Barrett <kbarrett@redhat.com>
 **              1.14    Added header & history. Minor formatting.
 **
 ** 02/07/2000   1.15 -  Keith Barrett <kbarrett@redhat.com>
 **              1.18    send_arp is in /usr/sbin
 **                      ignore tunl device when fetching hardware addrs
 **
 ** 02/15/2000   1.19 -  Keith Barrett <kbarrett@redhat.com>
 **              1.21    Lots of formatting and comments.
 **
 ** 2/23/2000    1.22 -  Keith Barrett <kbarrett@redhat.com>
 **              1.24    Added -v for debug output
 **                      Generic service option passing to nanny
 **
 ** 2/25/2000    1.25 -  Keith Barrett <kbarrett@redhat.com>
 **              1.30    Added call to lvsRelocateFS routine
 **                      If backupActive and no backup defined, clear it
 **                      Don't arp nat device if no nat device to use
 **
 ** 3/1/2000     1.31    Keith Barrett <kbarrett@redhat.com>
 **                      Added failover service logic
 **
 ** 3/2/2000     1.32    Phil "Bryce" Copeland <copeland@redhat.com>
 **                      Added processing of USR signals
 **                      Added config file copy
 **
 ** 3/4/2000     1.33 -  Keith Barrett <kbarrett@redhat.com>
 **              1.39    Fixed child signal problem with heartbeat
 **                      Added ability for fos to "takover" from master
 **                      if not the active node. Proclaimed stable.
 **                      2nd pulse daemon logic commented out in this file.
 **
 ** 3/6/2000     1.40 -  Keith Barrett <kbarrett@redhat.com>
 **              1.43    Replaced processing for USR signals, but disabled
 **                      the logic for this release because it's incomplete.
 **                      Don't run if all services are flagged as inactive.
 **
 ** 3/7/2000     1.44    Keith Barrett <kbarrett@redhat.com>
 **                      Clean up special take control heartbeat
 **                      Fixed lvs child term logic
 **                      Moved signal blocking to dup the old lvs logic
 **
** 6/13/2000    1.45    Keith Barrett <kbarrett@redhat.com>
**                      Fixed flags getting clobbered and screwing up
**                      the take control heartbeat.
**
** 6/14/2000    1.46    Keith Barrett <kbarrett@redhat.com>
**                      Changed "take control" heartbeat logic
**
** 6/18/2000    1.47    Keith Barrett <kbarrett@redhat.com>
**                      Added debugging to heartbeat logic
**
** 7/20/2000    1.48 -  Keith Barrett <kbarrett@redhat.com>
**              1.49    Changed debug mode & statements. Added --version.
**                      Added Bryce's CFGFILE logic.
**
** 8/17/2000    1.50    Lars Kellogg-Stedman <lars@larsshack.org>
**                      Fixed uninitialized size variable in heartbeat
**
** 9/11/2000	1.51	Philip Copeland <copeland@redhat.com>
**			            Fixed least connections to be lc not pcc
**
** 10/17/2000	1.52	Philip Copeland <bryce@redhat.com>
**                      Added extra --version info
**                      Fixed ifconfig up (should be down) for disabling
**                      interfaces
**
** 5/14/2001    1.53    Keith Barrett <kbarrett@redhat.com>
**                      Minor cleanup, added test-start.
**                      Suppress some errors on startup
**
** 5/30/2001    1.54    Keith Barrett <kbarrett@redhat.com>
**                      Corrected netmask impact on ifconfig and send arps.
**                      If starting FOS and no backup defined, force active.
**                      Renamed lvsProcess variable HA_process.
**
** 6/15/2001	1.55	Philip Copeland <bryce@redhat.com>
**			Globals from header file added
**
** 7/2/2001     1.56    Tim Waugh <twaugh@redhat.com>
**                      Heartbeat on dedicated interface
**                      Shared SCSI
**
** 7/30/2004    1.57    Florin Malita <fmalita@glenayre.com>
**                      Fixed /proc/net/dev scan routine - amMaster().
**
*/


#include <stdlib.h>		/* definition of exit() */
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <net/if.h>
#include <netinet/in.h>
#include <popt.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <unistd.h>
#include <pwd.h>
#include <setjmp.h>
#include <syslog.h>
#include <semaphore.h>
#include <time.h>
#include <pthread.h>

#include <sys/types.h>
#include <ifaddrs.h>

#include <sys/socket.h>
#include <netdb.h>

#include "globals.h"
#include "lvsconfig.h"
#include "util.h"

#define _PROGRAM_VERSION PULSE

#define _(a) (a)
#define N_(a) (a)

#define PULSE_FLAG_ASDAEMON         (1 << 0)
#define PULSE_FLAG_AMMASTER         (1 << 1)
#define PULSE_FLAG_AMACTIVE         (1 << 2)
#define PULSE_FLAG_NORUN            (1 << 3)
#define PULSE_FLAG_FAILPARTNER      (1 << 4)
#define PULSE_FLAG_RESTART_PARTNER  (1 << 5)
#define PULSE_FLAG_ONHOLD           (1 << 6)
#define PULSE_FLAG_SUPPRESS_GI_MSG  (1 << 7)
#define PULSE_FLAG_SUPPRESS_TC_MSG  (1 << 8)
#define PULSE_FLAG_SUPPRESS_ERRORS  (1 << 9)
#define PULSE_FLAG_LINKFAIL         (1 << 10)
#define PULSE_FLAG_CHILDFAIL        (1 << 11)

#define FOS_SERVICES_UP             (1 << 0)
#define FOS_MONITORS_UP             (1 << 1)

#define HEARTBEAT_RUNNING_MAGIC     0xbdaddbda
#define HEARTBEAT_STOPPED_MAGIC     0xadbddabd
#define HEARTBEAT_HOLD_MAGIC        0xDeafBabe
#define HEARTBEAT_HELD_MAGIC        0xDeafDaDa
#define FOS_HEARTBEAT_RUNNING_MAGIC 0xBeefBabe
#define FOS_HEARTBEAT_STOPPED_MAGIC 0xDeadBeef
#define FOS_HEARTBEAT_STOPME_MAGIC  0xDeadDaDa

#define COMMAND_DAEMON_PIPE_NAME        "/home/fes/commandDaemon.pipe"
#define PULSE_LOG_FILE			"/home/fes/logs/pulse.log"
#define LINE_DEBUG			0
#define DEBUG_LEVEL			0xff
#define debug_print(filename, level, fmt, args...)      \
	if(level & DEBUG_LEVEL) { \
		FILE *file_for_debug;   \
		struct stat filestat;   \
		if(0 == stat(filename,&filestat)) \
		{       \
			file_for_debug = fopen(filename, "ab+"); \
			if(file_for_debug){     \
				char sTime[32] = {0}; \
				time_t tNow = time(NULL); \
				strftime(sTime,sizeof(sTime)-1,"%d-%b-%Y %H:%M:%S",localtime(&tNow)); \
				if(LINE_DEBUG)\
				fprintf(file_for_debug, " %-15s:%-15s:%5d  "fmt"\n", __FILE__,__FUNCTION__,__LINE__, ##args);\
				else\
				fprintf(file_for_debug, "pid:%d(0x%x) %s "fmt"\n",getpid(),pthread_self(),sTime,##args);\
				fclose(file_for_debug); \
			}       \
		}       \
	}       \
else{   do{;}while(0);\
}

#define HA_COMMON_LOGS                                          "/home/fes/logs/ha.log"
extern const char *__progname;
/* Globals icky :-( */
pid_t piranha;
pid_t pid;
struct sigaction sig;
int gflag = 0;

static char *configFile = (char *) CFGFILE;	/* Supplied by globals.he */
static char *lvsBinary = (char *) "/usr/sbin/lvsd";
static char *fosBinary = (char *) "/usr/sbin/fos";
static int pulse_debug = 0;
static const int scsires_holdtime = 4;	/* seconds; should be configurable */

volatile int termSignal = 0;
volatile int childSignal = 0;
volatile int User1Signal = 0;
volatile int alarmSignal = 0;
volatile pid_t HA_Process = 0;
volatile pid_t SCSI_Process = 0;

static int deadtimeout_expired_after_fail_cond = 0;
static int hearbeat_recieved_after_link_or_network_fail = 1;
int heartbeat_running_magic = (int) HEARTBEAT_RUNNING_MAGIC;
int heartbeat_stopped_magic = (int) HEARTBEAT_STOPPED_MAGIC;

#define NTP_SERVER_CONF_FILE		"/home/fes/ntpserver.conf"
#define DEFAULT_NTPINTERVAL		5
static int ntpInterval = 0;

/* These are the states that we can be in when shared SCSI devices
   are being used. */
enum reserve_state
{
	rs_backup,			/* Backup node, heartbeat OK */
	rs_active,			/* Active node, heartbeat OK */
	rs_reserving_dev,		/* Backup node, trying to take over from dead node */
	rs_resetting_bus,		/* Backup node, trying to break stale reservation */
	rs_waiting,			/* Backup node, waiting to receive heartbeat msg */
	rs_preempting			/* Backup node, trying to take over from partially */
		/* dead node (which is still able to reserve device) */
}
fos_reserve_state = rs_backup;

/* Gateway-awareness */
//static pid_t ping_process; /* initially zero automatically */
//static int ping_retries; /* initially zero automatically */
//static char gateway[16]; /* initially zero automatically */
//static int network_fault; /* initially zero automatically */

/* prototypes */
void relay (int s);
void house_keeping (int s);
void initsetproctitle (int argc, char **argv, char **envp);
void setproctitle (const char *fmt, ...);
int ip_check_link(struct in_addr set_addr);

	static void
handleTermSignal(int signal)
{
	//debug_print(PULSE_LOG_FILE,8,"Pulse Got SIGTERM or SIGINT.");	
	termSignal = signal;
}

	static void
handleChildDeath(int signal)
{
	//debug_print(PULSE_LOG_FILE,8,"Pulse Got SIGCHLD.");
	childSignal = signal;
	/* This is only possible with fos. */
}

	static void
handleAlarmSignal(int signal)
{
	alarmSignal = signal;
	/* This is only possible with fos. */
}

static void handleHupSignal(int signal) 
{
	//debug_print(PULSE_LOG_FILE,8,"Pulse got HUP signal.")
	kill(HA_Process, SIGHUP);
}

/*
 **  getInterfaceAddress() -- Get address of a network device
 */

	static int
getInterfaceAddress(int s, char *device, struct in_addr *addr, int flags)
{
	struct ifreq req;
	struct sockaddr_in *addrp;

	strcpy (req.ifr_name, device);

	if (ioctl (s, SIOCGIFADDR, &req))
	{
		if (strncmp ("tunl", device, 4))	/* log only if not tunl dev */
			piranha_log (flags,
					(char *) "SIOCGIFADDR failed: %s", strerror (errno));
		/*
		 ** Note: suppress errors about tunl because it's in /proc even
		 ** if it is not being used, so it will appear here.
		 */

		return 1;
	}

	addrp = (struct sockaddr_in *) &req.ifr_addr;
	memcpy (addr, &addrp->sin_addr, sizeof (*addr));
	return 0;
}


/*
 **  getInterfaceInfo() -- get mac address for validated device
 */

	static void
getInterfaceInfo (int s,
		char *device, struct in_addr *addr, char *hwaddr, int flags)
{

	struct ifreq req;
	struct sockaddr_in *addrp;

	strcpy(req.ifr_name, device);

	if(ioctl(s, SIOCGIFBRDADDR, &req))
	{
		piranha_log (flags,
				(char *) "SIOCGIFBRDADDR failed: %s", strerror (errno));
		return;
	}

	addrp = (struct sockaddr_in *) &req.ifr_addr;
	memcpy(addr, &addrp->sin_addr, sizeof (*addr));

	if(ioctl(s, SIOCGIFHWADDR, &req))
	{
		piranha_log (flags,
				(char *) "SIOCGIFHWADDR failed: %s", strerror (errno));
		return;
	}

	memcpy(hwaddr, req.ifr_hwaddr.sa_data, IFHWADDRLEN);
}


/*
 **  disableInterface() -- Disable ('ifconfig xxx down') an interface
 */
	static void
disableInterface (char *device, int flags)
{
	pid_t child;
	char *ifconfigArgs[5];
	int i = 0;

	ifconfigArgs[i++] = (char *) "/sbin/ifconfig";

	ifconfigArgs[i++] = device;
	ifconfigArgs[i++] = (char *) "down";
	ifconfigArgs[i++] = NULL;
	ifconfigArgs[4] = NULL;

	if(pulse_debug)
		piranha_log (flags,
				(char *)
				"DEBUG -- Executing '/sbin/ifconfig %s down'", device);
	if(!(child = fork()))
	{
		logArgv(flags, ifconfigArgs);
		execv(ifconfigArgs[0], ifconfigArgs);
		exit(-1);
	}

	waitpid(child, NULL, 0);
}

/*
 **  sendArps() -- send arps for a device, mac address, and ip address combo
 */
	static void
sendArps (char *device,
		struct in_addr *address,
		struct in_addr *vip_nmask, int num, int flags)
{
	int i;
	int s;
	char *floatAddr = strdup(inet_ntoa(*address));
	char *netmask = strdup(inet_ntoa(*vip_nmask));

	struct in_addr bcast;

	char *broadcast = NULL;
	struct in_addr addr;
	char hwaddr[IFHWADDRLEN];
	char hwname[20];
	pid_t child;
	char *ifconfigArgs[10];
	char *ifconfigArgsFull[10];
	char *sendArpArgv[10];
	int netmask_specified = 0;


	sendArpArgv[0] = (char *) "/usr/sbin/send_arp";
	sendArpArgv[1] = (char *) "-i";
	sendArpArgv[2] = device;
	sendArpArgv[3] = floatAddr;
	sendArpArgv[4] = hwname;
	sendArpArgv[5] = broadcast;
	sendArpArgv[6] = (char *) "ffffffffffff";
	sendArpArgv[7] = NULL;

	ifconfigArgs[0] = (char *) "/sbin/ifconfig";
	ifconfigArgs[1] = device;
	ifconfigArgs[2] = floatAddr;
	ifconfigArgs[3] = (char *) "up";
	ifconfigArgs[4] = NULL;

	if(vip_nmask)
	{
		if(vip_nmask->s_addr)
			netmask_specified = -1;
		/* if network mask ptr is OK, AND it points to a non-zero value */
	}


	if(netmask_specified)
	{
		/* A small calculation for to get the broadcast */
		bcast.s_addr =
			(address->s_addr & vip_nmask->s_addr) | ~vip_nmask->s_addr;

		ifconfigArgsFull[0] = (char *) "/sbin/ifconfig";
		ifconfigArgsFull[1] = device;
		ifconfigArgsFull[2] = floatAddr;
		ifconfigArgsFull[3] = (char *) "netmask";
		ifconfigArgsFull[4] = netmask;
		ifconfigArgsFull[5] = (char *) "broadcast";
		ifconfigArgsFull[6] = (char *) inet_ntoa (bcast);
		ifconfigArgsFull[7] = (char *) "up";
		ifconfigArgsFull[8] = NULL;
	}

#if 0
	if(!(child = fork ()))
	{
		if(netmask_specified)
		{
			logArgv(flags, ifconfigArgsFull);

			if(pulse_debug)
				piranha_log (flags, (char *)
						"DEBUG -- Executing '/sbin/ifconfig %s %s netmask %s up'",
						device, floatAddr, netmask);
			debug_print(PULSE_LOG_FILE,8,"DEBUG -- Executing '/sbin/ifconfig %s %s netmask %s broadcast %s up'", device, floatAddr, netmask, inet_ntoa (bcast));
			execv(ifconfigArgs[0], ifconfigArgsFull);

		}
		else
		{
			logArgv(flags, ifconfigArgs);

			if(pulse_debug)
				piranha_log (flags, (char *)"DEBUG -- Executing '/sbin/ifconfig %s %s up'",device, floatAddr);

			debug_print(PULSE_LOG_FILE,8,"DEBUG -- Executing '/sbin/ifconfig %s %s up'", device, floatAddr);
			execv(ifconfigArgs[0], ifconfigArgs);
		}
		
		exit(-1);
	}

	waitpid(child, NULL, 0);
#endif

#if 1
	FILE* fp = NULL;
	char popen_buffer[512] = {0};
	char command[512] = {0};
	
	if(netmask_specified)
	{
		logArgv(flags, ifconfigArgsFull);

		if(pulse_debug)
			piranha_log (flags, (char *)
					"DEBUG -- Executing '/sbin/ifconfig %s %s netmask %s up'",
					device, floatAddr, netmask);
					
		sprintf(command,"/sbin/ifconfig %s %s netmask %s broadcast %s up",device, floatAddr, netmask, inet_ntoa (bcast));
		
		debug_print(PULSE_LOG_FILE,8,"DEBUG -- Executing '%s'", command);
	    fp = popen(command, "r");
	

	}
	else
	{
		logArgv(flags, ifconfigArgs);

		if(pulse_debug)
			piranha_log (flags, (char *)"DEBUG -- Executing '/sbin/ifconfig %s %s up'",device, floatAddr);
		sprintf(command,"/sbin/ifconfig %s %s up",device, floatAddr);
		
		debug_print(PULSE_LOG_FILE,8,"DEBUG -- Executing '%s'", command);
		fp = popen(command, "r");
	}
	errno=0;
	if(fp != NULL)
	{
		fread(popen_buffer, 1, 512, fp);
		debug_print(PULSE_LOG_FILE,8,"Output of popen is : [%s]",popen_buffer);
		int ret_val = pclose(fp);
		if(ret_val == -1)
		{
			debug_print(PULSE_LOG_FILE,8,"Error occured while runing ifconfig %s",strerror(errno));
		}
	}
#endif
	device = strdup (device);

	if(strchr(device, ':'))
		*strchr(device, ':') = '\0';

	sendArpArgv[2] = device;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	getInterfaceInfo(s, device, &addr, hwaddr, flags);
	close(s);

	for(i = 0; i < 6; i++)
	{
		sprintf(hwname + (i * 2), "%02X", ((unsigned int) hwaddr[i]) & 0xFF);
	}

	broadcast = inet_ntoa(addr);

	sendArpArgv[4] = hwname;
	sendArpArgv[5] = broadcast;

	logArgv(flags, sendArpArgv);

	if(pulse_debug)
		piranha_log (flags, (char *) "DEBUG -- Executing '/usr/sbin/send_arp'");

	debug_print(PULSE_LOG_FILE,8,"DEBUG -- Executing '/sbin/send_arp -i %s %s %s %s ffffffffffff'", device, floatAddr, hwname, broadcast);

	for(i = 0; i < num; i++)
	{
		if(!(child = fork ()))
		{
			execv(sendArpArgv[0], sendArpArgv);
			exit(1);
		}

		waitpid (child, NULL, 0);
		sleep (1);
	}
}


/*
 ** syncDaemon() -- (re)start IPVS synchronisation daemon
 */

	static void
syncDaemon (struct lvsConfig *config, int flags, int master)
{

	pid_t child;
	char *ipvsadmArgs[8];
	char id[4];

	if (config->useSyncDaemon == 0)
		return;

	ipvsadmArgs[0] = (char *) config->vsadm;
	ipvsadmArgs[1] = (char *) "--stop-daemon";
	ipvsadmArgs[2] = (char *) "backup";
	ipvsadmArgs[3] = NULL;

	if (pulse_debug)
		piranha_log (flags,
				(char *)
				"DEBUG -- Executing 'ipvsadm --stop-daemon %s'", ipvsadmArgs[2]);

	if (!(child = fork ()))
	{
		logArgv (flags, ipvsadmArgs);
		execv (ipvsadmArgs[0], ipvsadmArgs);
		exit (-1);
	}

	waitpid (child, NULL, 0);

	ipvsadmArgs[0] = (char *) config->vsadm;
	ipvsadmArgs[1] = (char *) "--stop-daemon";
	ipvsadmArgs[2] = (char *) "master";
	ipvsadmArgs[3] = NULL;

	if (pulse_debug)
		piranha_log (flags,
				(char *)
				"DEBUG -- Executing 'ipvsadm --stop-daemon %s'", ipvsadmArgs[2]);

	if (!(child = fork ()))
	{
		logArgv (flags, ipvsadmArgs);
		execv (ipvsadmArgs[0], ipvsadmArgs);
		exit (-1);
	}

	waitpid (child, NULL, 0);

	sprintf (id, "%d", (config->syncdID & 0xff));

	ipvsadmArgs[0] = (char *) config->vsadm;
	ipvsadmArgs[1] = (char *) "--start-daemon";
	ipvsadmArgs[2] = (char *) ((master) ? "master" : "backup");
	ipvsadmArgs[3] = (char *) "--mcast-interface";
	ipvsadmArgs[4] = (char *) config->syncdInterface;
	ipvsadmArgs[5] = (char *) "--syncid";
	ipvsadmArgs[6] = (char *) id;
	ipvsadmArgs[7] = NULL;

	if (pulse_debug)
		piranha_log (flags,
				(char *)
				"DEBUG -- Executing 'ipvsadm --start-daemon %s --mcast-interface %s --syncid %s'",
				ipvsadmArgs[2], ipvsadmArgs[4], ipvsadmArgs[6]);

	if (!(child = fork ()))
	{
		logArgv (flags, ipvsadmArgs);
		execv (ipvsadmArgs[0], ipvsadmArgs);
		exit (-1);
	}

	waitpid (child, NULL, 0);
}

/*
 **  sendLvsArps() -- send arps for all VIPs
 */
	static void
sendLvsArps (struct lvsConfig *config, int flags)
{
	pid_t fake1;
	pid_t *fake = alloca (sizeof (*fake) * (config->numVirtServers + 1));
	int i;
	int j;
	int numFakes;

	/* Run fake for 5 seconds on each interface */
	if (!(fake1 = fork ()))
	{
		if(fork ())
		{
			exit (0);
		}

		/* we're init's problem now */

		numFakes = 0;

		if(!(fake[numFakes++] = fork ()))
		{
			if ((config->redirectType == LVS_REDIRECT_NAT) &&
					(config->natRouterDevice != NULL))
				sendArps (config->natRouterDevice,
						&config->natRouter, &config->nat_nmask, 5, flags);
			/* send arps to nat router (if any) */
			exit (1);
		}


		for(i = 0; i < config->numVirtServers; i++)
		{
			if(!config->virtServers[i].isActive)
				continue;

			if(config->virtServers[i].failover_service)
			{
				piranha_log (flags,
						(char *) "Warning; skipping failover service");
				continue;		/* This should not be possible anymore */
			}

			for(j = 0; j < i; j++)
			{
				if(!config->virtServers[j].isActive)
					continue;

				if(!memcmp(&config->virtServers[i].virtualAddress,
							&config->virtServers[j].virtualAddress,
							sizeof (config->virtServers[i].virtualAddress)))
					break;
			}

			if(j == i)
			{
				if(!(fake[numFakes++] = fork ()))
				{
					sendArps(config->virtServers[i].virtualDevice,
							&config->virtServers[i].virtualAddress,
							&config->virtServers[i].vip_nmask, 5, flags);
					exit (1);
				}
			}
		}

		for(i = 0; i < numFakes; i++)
			waitpid(fake[i], NULL, 0);

		piranha_log(flags,(char *)"gratuitous lvs arps finished");

		exit(0);
	}

	waitpid (fake1, NULL, 0);
}

/*
 **  executeCommand() -- 
 */
	static void
executeCommand (struct lvsConfig *config, int flags, char *cmd)
{
	pid_t child = 0;
	char *argv[40];
	char **argp;
	char *token;
	char *command;

	if(!cmd)
		return;

	command = strdup(cmd);

	if(!(flags & PULSE_FLAG_NORUN))
	{
		if(pulse_debug)
			piranha_log(flags,(char *)"DEBUG--Executing '%s'",command);

		if(!(child = fork()))
		{
			debug_print(PULSE_LOG_FILE,8,"Executing command [%s]",command);
			argp = argv;
			token = strtok(command," ");
			while(token != NULL)
			{
				*argp++ = strdup(token);
				token = strtok(NULL," ");
			}
			
			*argp++ = NULL;

			logArgv(flags, argv);
			execv(argv[0], argv);
			exit(-1);
		}

		//waitpid (child, NULL, 0);
	}

	free(command);
}

/*
 **  activateLvs() -- Start LVS program, then send arps for all VIPs
 */
	static pid_t
activateLvs (struct lvsConfig *config, int flags)
{

	pid_t child = 0;
	char *argv[6];
	sem_t *sem = NULL;
	struct timespec ts;

	executeCommand (config, flags, config->activeCommand);

	argv[0] = lvsBinary;
	argv[1] = (char *) "--nodaemon";
	argv[2] = (char *) "-c";
	argv[3] = configFile;
	argv[4] = NULL;
	argv[5] = NULL;

	if (flags & PULSE_FLAG_ASDAEMON)
		argv[1] = (char *) "--nofork";

	if (pulse_debug)
		argv[4] = (char *) "-v";

	if (pulse_debug)
		logArgv (flags, argv);

	if ((sem = sem_open (LVS_MUTEX, O_CREAT, 0644, 0)) == SEM_FAILED) {
		piranha_log (flags, (char *) "Failed to open semaphore: %s", strerror(errno));
		sem_unlink (LVS_MUTEX);
		exit (-1);
	}

	if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
		piranha_log (flags, (char *) "Failed to get current time: %s", strerror(errno));
		sem_unlink (LVS_MUTEX);
		exit (-1);
	}

	/*
	 * 10 seconds is a long time to wait for semaphore...
	 */
	ts.tv_sec += 10;

	if (!(flags & PULSE_FLAG_NORUN)) {
		if (!(child = fork ())) {
			execv (lvsBinary, argv);
			exit (-1);
		}

		do {
			if (sem_timedwait (sem, &ts) != 0) {
				if (errno == EINTR)
					continue;
				piranha_log (flags, (char *) "Error waiting for semaphore: %s", strerror(errno));
				sem_unlink (LVS_MUTEX);
				kill (child, SIGKILL);
				exit (-1);
			}
		} while (0);

		sem_unlink (LVS_MUTEX);
	}

	syncDaemon (config, flags, 1);
	sendLvsArps (config, flags);

	return child;
}


int SendCommandToDaemon(int flags, char* command)
{
        int fd,retStatus;
        debug_print(PULSE_LOG_FILE,8,"[%s] Sending Command [%s] To Command Server.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",command);
        fd = open(COMMAND_DAEMON_PIPE_NAME, O_WRONLY|O_NONBLOCK);       //COMMAND_DAEMON_PIPE_NAME /home/fes/commDemon.txt
        if(fd)
        {
                retStatus = write(fd,command,strlen(command));
                if(retStatus == -1)
                {
                        if(retStatus == EPIPE)
                        {
                                debug_print(PULSE_LOG_FILE,8,"[%s] Failed To Write over pipe command %s",
					(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",command);
                        }
                        close(fd);
                        return 0;
                }
                close(fd);
                return 1;
        }
        else
	{
                debug_print(PULSE_LOG_FILE,8,"[%s] Failed To Open Pipe for command %s",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",command);
                return 0;
        }
}

/*
 **  deactiveLVS() --  stop LVS process and shut down all VIP interfaces
 */

	static void
deactivateLvs(struct lvsConfig *config, int flags, int executeInactiveCommand)
{
	int i, j;

	if(executeInactiveCommand == 1)
	{
		executeCommand(config, flags, config->inactiveCommand);
	}
	else
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] Pulse exiting on sigterm, so stopping infoagent and filesync",
				(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
		char commandKillInfoAgentFileSync[] = "KILL_SYNC_INFO";
		if(!SendCommandToDaemon(flags, commandKillInfoAgentFileSync))
        	{
                	debug_print(PULSE_LOG_FILE,8,"[%s] Failed To Send Command to Stop infoagent and sync.",
				(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
          	}	
	}
	
	syncDaemon(config, flags, 0);

	if((flags & PULSE_FLAG_NORUN) || !(flags & PULSE_FLAG_AMACTIVE))
		return;

	kill(HA_Process, SIGTERM);
	/* XXX need a timeout here, which means an alarm, which is gross */
	waitpid(HA_Process, NULL, 0);
	HA_Process = 0;
	/* deactivate the interfaces */
	for(i = 0; i < config->numVirtServers; i++)
	{
		if(!config->virtServers[i].isActive)
			continue;

		if(config->virtServers[i].failover_service)
		{
			piranha_log(flags,(char *)"Warning; skipping failover service");
			continue;		/* This should not be possbile anymore */
		}

		for(j = 0; j < i; j++)
		{
			if(!config->virtServers[j].isActive)
				continue;

			if(!memcmp(&config->virtServers[i].virtualAddress,
						&config->virtServers[j].virtualAddress,
						sizeof(config->virtServers[i].virtualAddress)))
				break;
		}

		if(j == i)
			disableInterface(config->virtServers[i].virtualDevice, flags);
	}

	if((config->redirectType == LVS_REDIRECT_NAT) &&
			(config->natRouterDevice != NULL))
		disableInterface(config->natRouterDevice, flags);
}





/*
 **  createSocket() -- Create heartbeat socket
 */

	static int
createSocket (struct in_addr *addr, int port, int flags)
{

	int sock;
	long sock_flags;
	struct sockaddr_in address;


	if ((sock = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
	{
		piranha_log (flags, (char *) "failed to create UDP socket: %s",
				strerror (errno));
		return 1;
	}

	address.sin_family = AF_INET;
	address.sin_port = htons (port);
	memcpy (&address.sin_addr, addr, sizeof (*addr));

	if (bind (sock, (struct sockaddr *) &address, sizeof (address)))
	{
		piranha_log (flags, (char *) "failed to bind to heartbeat address: %s",
				strerror (errno));
		return -1;
	}

	/* Set close on exec bit so children don't have the port bound */
	sock_flags = fcntl(sock, F_GETFD);
	sock_flags |= FD_CLOEXEC;
	fcntl(sock, F_SETFD, sock_flags);

	return sock;
}

/*
 ** processSignals() -- Process any signals that have arrived
 */
static int processSignals (struct lvsConfig *config, int *flags, int use_fos, sigset_t * sigs)
{
	pid_t child = 0;
	int status;

	if((childSignal != 0) && (use_fos == 0))
	{
		sigprocmask(SIG_BLOCK, sigs, NULL);
		signal(SIGCHLD, handleChildDeath);

		if((child = waitpid (-1, &status, WNOHANG)) > 0)
		{
			if(child == HA_Process)
			{
				if(WIFEXITED(status))
				{
					piranha_log(*flags, "Child process %d exited with status %d",
							child, WEXITSTATUS (status));
				}
				
				if(WIFSIGNALED(status))
				{
					piranha_log(*flags, "Child process %d terminated with signal %d",
							child, WTERMSIG (status));
				}

				deactivateLvs(config, *flags, 1);
				*flags &= (~PULSE_FLAG_AMACTIVE);
				*flags |= (PULSE_FLAG_CHILDFAIL);
			}
			else
			{
				piranha_log(*flags,"Skipping death of unknown child %d", child);
			}
		}

		childSignal = 0;
		sigprocmask(SIG_UNBLOCK, sigs, NULL);
	}

	if(termSignal != 0)
	{
		piranha_log(*flags,"Terminating due to signal %d",termSignal);
		deactivateLvs(config, *flags, 0);
		termSignal = 0;
		return 1;
	}

	return 0;
}

int check_link_status(struct lvsConfig *config, int *flags)
{
	char addrtomatch[64] = {0};	

	if(*flags & PULSE_FLAG_AMMASTER)
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] Checking link status in case of master node for addresses [%s] and [%s].",
			(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",inet_ntoa(config->primaryServer),inet_ntoa(config->primaryPrivate));
		strcpy(addrtomatch,inet_ntoa(config->primaryServer));
	}
	else
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] Checking link status in case of backup node for addresses [%s] and [%s].",
			(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",inet_ntoa(config->backupServer),inet_ntoa(config->backupPrivate));

		strcpy(addrtomatch,inet_ntoa(config->backupServer));
	}

	struct ifaddrs *ifaddr = NULL, *ifa;
	int family, s;
	char host[256]; //NI_MAXHOST];	

	if(getifaddrs(&ifaddr) == -1)
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] getifaddrs failed, error %s",
				(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strerror(errno));
		return 1;	
	}
	
	for(ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) 
	{
        	if(ifa->ifa_addr == NULL)
            		continue;

       		family = ifa->ifa_addr->sa_family;
		
		if(family == AF_INET)
		{
			s = getnameinfo(ifa->ifa_addr, sizeof(struct sockaddr_in), host, sizeof(host), NULL, 0, NI_NUMERICHOST);
			if(s != 0) 
			{
				debug_print(PULSE_LOG_FILE,8,"[%s] getnameinfo() failed: %s.",
					(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",gai_strerror(s));
				if(ifaddr)
				{
					freeifaddrs(ifaddr);
					ifaddr = NULL;
				}

				return 1;
			}

			if(!strcmp(host,addrtomatch))
			{
				debug_print(PULSE_LOG_FILE,8,"[%s] address matched", 
					(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

				if((ifa->ifa_flags & IFF_UP) && (ifa->ifa_flags & IFF_RUNNING))
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] Link is up and Running",
						(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					if(ifaddr)
                                	{
						freeifaddrs(ifaddr);
						ifaddr = NULL;
                                	}

					return 1;
				}
				else
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] Link is down and dead",
                                                (*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

					if((ifa->ifa_flags & IFF_UP))
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Link is UP. But not Running.",
                                                (*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					}
					else if((ifa->ifa_flags & IFF_RUNNING))
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Link is down, But Running.",
                                                (*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					}
					
					if(ifaddr)
					{
						freeifaddrs(ifaddr);	
						ifaddr = NULL;
					}
	
					return 0;
				}				
			}	
		}
	}

	if(ifaddr)
		freeifaddrs(ifaddr);
	return 1;
}
	int
check_links(struct lvsConfig *config, int *flags)
{
	int ret = 1;

	if(!config->monitorLinks)
	{
		debug_print(PULSE_LOG_FILE,8,"Monitor links is not set.");	
		return 1; /* If we're not monitoring links, always return true */
	}

	if(!config->backupActive)
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] backup is already set deactive.",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
		return 1; /* If we're monitoring links but no backup, disable...
			     us being quasi-up is better than nothing up at all */
	}

	/* Ok check the links */
	if(*flags & PULSE_FLAG_AMMASTER)
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] Checking link status in case of master node for addresses [%s] and [%s].",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",inet_ntoa(config->primaryServer),inet_ntoa(config->primaryPrivate));
		if(!ip_check_link(config->primaryServer))
		{
			if (!(*flags & PULSE_FLAG_LINKFAIL))
				piranha_log(*flags, "Primary NIC: link down");

			debug_print(PULSE_LOG_FILE,8,"[%s] primary server is detected down.",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			ret = 0;
		}
		
		if(strcmp(inet_ntoa(config->primaryServer),inet_ntoa(config->primaryPrivate)))
		{
			if(!ip_check_link(config->primaryPrivate))
			{
				if(!(*flags & PULSE_FLAG_LINKFAIL))
					piranha_log(*flags, "Private NIC: link down");

				debug_print(PULSE_LOG_FILE,8,"[%s] primary private server is detected down.",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
				ret = 0;
			}
		}
		
		return ret;
	}

	/* We're the backup, check the backup server links */
	debug_print(PULSE_LOG_FILE,8,"[%s] Checking link status in case of backup node for addresses [%s] and [%s].",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",inet_ntoa(config->backupServer),inet_ntoa(config->backupPrivate));
	if(!ip_check_link(config->backupServer))
	{
		if (!(*flags & PULSE_FLAG_LINKFAIL))
			piranha_log(*flags, "Primary NIC: link down");
		debug_print(PULSE_LOG_FILE,8,"[%s] backup server is detected down.",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
		ret = 0;
	}

	if(strcmp(inet_ntoa(config->backupServer),inet_ntoa(config->backupPrivate)))
	{	
		if(!ip_check_link(config->backupPrivate))
		{
			if (!(*flags & PULSE_FLAG_LINKFAIL))
				piranha_log(*flags, "Private NIC: link down");
			debug_print(PULSE_LOG_FILE,8,"[%s] backup private server is detected down.",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			ret = 0;
		}
	}
	
	return ret;
}


	void
send_heartbeat (struct lvsConfig *config, int sock, int sock_priv, int *flags,
		struct sockaddr_in *partner, struct sockaddr_in *partner_priv)
{
	unsigned int magic = heartbeat_stopped_magic;
	int rc;

	/* If there's no backup server specified, then there's nothing to do. */
	if(!config->backupActive)
		return;

	if(*flags & PULSE_FLAG_AMACTIVE)
		magic = heartbeat_running_magic;

	if(*flags & PULSE_FLAG_FAILPARTNER)
	{
		if((*flags & PULSE_FLAG_SUPPRESS_TC_MSG) == 0)
		{
			piranha_log (*flags, (char *)
					"Notifying partner WE are taking control!");
			*flags |= PULSE_FLAG_SUPPRESS_TC_MSG;
		}

		magic = FOS_HEARTBEAT_STOPME_MAGIC;
		/* Special case where fos forces partner to go inactive */
	}

	if(pulse_debug)
		piranha_log (*flags, (char *) "DEBUG -- Sending heartbeat...");

	debug_print(PULSE_LOG_FILE,8,"[%s] Sending heartbeat",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
	/* Send to partner's IP address over public interface */
	rc = sendto(sock, &magic, sizeof (magic), (int) 0,
			(struct sockaddr *) partner,
			(socklen_t) sizeof (*partner));

	if((rc == -1) && (pulse_debug != 0))
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] sendto error %s",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strerror(errno));
		piranha_log (*flags, (char *)
				"Warning -- failed to send heartbeat (public if): %s",
				strerror (errno));
	}

	if(sock_priv == -1 || !partner_priv)
		return;

	/* Send to partner's IP address over private interface */
	rc = sendto(sock_priv, &magic, sizeof (magic), (int) 0,
			(struct sockaddr *) partner_priv,
			(socklen_t) sizeof (*partner_priv));
	if((rc == -1) && (pulse_debug != 0))
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] sendto error %s",(*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strerror(errno));
		piranha_log (*flags, "Warning -- failed to send "
				"heartbeat (private if): %s",
				strerror (errno));
	}
}

/*
   Pull this out so we can shutdown without duplicating the 
   block of code...
   */
#define shutdown_services(msg) \
	do { \
		/* Virtual Services */ \
		piranha_log (flags, (char *)msg ": deactivating LVS"); \
		deactivateLvs (config, flags, 1); \
		flags &= (~PULSE_FLAG_AMACTIVE); \
	} while(0)

#define startup_services(msg) \
	do { \
		{ \
			piranha_log (flags, \
					(char *) msg ": activating lvs"); \
			HA_Process = activateLvs (config, flags); \
			flags |= PULSE_FLAG_AMACTIVE; \
		} \
	} while (0)


/*
 **  run() -- main login routine
 */

void PutInHALogs(char *msg)
{
        char sTime[32] = {0};
        FILE *fp = fopen(HA_COMMON_LOGS,"a");
        if(fp)
        {
                setvbuf(fp,NULL,_IONBF,0);
                time_t tNow = time(NULL);
                strftime(sTime,sizeof(sTime)-1,"%d-%b-%Y %H:%M:%S",localtime(&tNow));
                fprintf(fp,"%s, %8u, %12s, %s\n",sTime,(unsigned int)getpid(),__progname,msg);
                fclose(fp);
        }
}

int IsNetworkConnectivityBroken(struct sockaddr_in *partner, int flags)
{
#if 0
	int sock = -1;
	struct sockaddr_in remote;
	
	sock = socket(AF_INET , SOCK_STREAM , 0);
	if(sock == -1)
	{
		debug_print(PULSE_LOG_FILE,8,"[%s] socket error %s",
				(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive", strerror(errno));
		return 1;
	}

	remote.sin_family = AF_INET;
	remote.sin_port = htons(8888);
	memcpy(&(remote.sin_addr),&(partner->sin_addr),sizeof (struct in_addr));

	errno = 0;
	if(connect(sock, (struct sockaddr *)&remote, sizeof(remote)) < 0)
	{
		if(errno != ECONNREFUSED)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Connectivity error %s.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive", strerror(errno));
			close(sock);
			return 1;
		}
		else
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Partner is up..",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");	
			close(sock);
			return 0;
		}
	}

	close(sock);
	return 1;	
#endif

	//char cmd[] = "/usr/bin/ping -n -w 1 -c 1 $(/usr/sbin/route -n | /usr/bin/grep \"UG\" | /usr/bin/grep \"0.0.0.0\" | /usr/bin/awk '{ print $2}' | head -1) > /dev/null 2>&1; echo $?";
	char cmd[] = "/sbin/arping -I $(/usr/sbin/route -n | /usr/bin/grep \"UG\" | /usr/bin/grep \"0.0.0.0\" | /usr/bin/awk '{ print $8}' | head -1) -w 2 -f $(/usr/sbin/route -n | /usr/bin/grep \"UG\" | /usr/bin/grep \"0.0.0.0\" | /usr/bin/awk '{ print $2}' | head -1) > /dev/null 2>&1; echo $?";
	FILE* fp = NULL;
        char strfp[4] = {0};
       	int st;

	signal (SIGCHLD, SIG_IGN);//handleChildDeath);
	debug_print(PULSE_LOG_FILE,8,"[%s] command fired is %s..",
                                                                (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",cmd); 
	fp = popen(cmd,"r");
        if(fp != NULL)
        {
                fread(strfp,1,4,fp);
		debug_print(PULSE_LOG_FILE,8,"[%s] Read bytes are %s..",
                                                                (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strfp);
		if(strlen(strfp))
		{
			if(strfp[strlen(strfp)-1] == '\n')
				strfp[strlen(strfp)-1] = '\0';

			debug_print(PULSE_LOG_FILE,8,"[%s] Read bytes after newline removed %s.. len is %d",
                                                                (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strfp,strlen(strfp));
			//if(strlen(strfp) == 1)
			{
				st = atoi(strfp);
				if(st)
				{
					pclose(fp);
					debug_print(PULSE_LOG_FILE,8,"[%s] Default gateway is unreachable..",
                                                                (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					signal (SIGCHLD, handleChildDeath);
					return 1;
				}
				else
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] Default gateway is reachable...",
                                                                (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					pclose(fp);
					signal (SIGCHLD, handleChildDeath);
					return 0;
				}	
			}
		}	
                
		pclose(fp);
		signal (SIGCHLD, handleChildDeath);
                return 0;
        }
        
	signal (SIGCHLD, handleChildDeath);
	return 0;
	
}

int SyncTimeWithNTPServer(char *ntp, struct lvsConfig *config, int sock, int sock_priv, int *flags, 
				struct sockaddr_in *partner, struct sockaddr_in *partner_priv)
{
	pid_t child;
	int maxtries = 6;
	int status = 0;
	int ret;
	int retpid;

	char *ntpcommand[6];
	int i = 0;

	ntpcommand[i++] = (char*) "/usr/sbin/ntpdate";
	ntpcommand[i++] = ntp;
	ntpcommand[i++] = ">";
	ntpcommand[i++] = "/dev/null";
	ntpcommand[i++] = NULL;
	ntpcommand[5] = NULL;

	if(!(child = fork ()))
        {
                //logArgv(flags, ifconfigArgs);
                execv(ntpcommand[0], ntpcommand);
                exit(-1);
        }

	send_heartbeat(config, sock, sock_priv, flags, partner, partner_priv);
	while(maxtries > 0)
	{
		errno = 0;
		ret = sleep(config->keepAliveTime);
		if(ret == 0)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Sleep timer expired in ntpdate, sending a heartbeat.",
                                                (*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			send_heartbeat(config, sock, sock_priv, flags, partner, partner_priv);		
		}	
	
		maxtries--;	
		retpid = waitpid(child, NULL, WNOHANG);
		if(retpid == child)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] ntpdate command returned.", (*flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			status = 1;
			break;
		}
	}

	return status;		
}

#if 0
int SyncTimeWithNTPServer(int flags, char* ntp)
{
	char cmd[1024] = {0};
	FILE* fp = NULL;
	char strfp[4] = {0};
	int st;

	sprintf(cmd,"/usr/sbin/ntpdate %s > /dev/null 2>&1; echo $?",ntp);
	
	signal(SIGCHLD, SIG_IGN);//handleChildDeath);
	debug_print(PULSE_LOG_FILE,8,"[%s] command fired is %s..",
			(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",cmd); 
	fp = popen(cmd,"r");
	if(fp != NULL)
	{
		fread(strfp,1,4,fp);
		debug_print(PULSE_LOG_FILE,8,"[%s] Read bytes are %s..",
				(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strfp);
		if(strlen(strfp))
		{
			if(strfp[strlen(strfp) - 1] == '\n')
				strfp[strlen(strfp) - 1] = '\0';

			debug_print(PULSE_LOG_FILE,8,"[%s] Read bytes after newline removed %s.. len is %d",
					(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strfp,strlen(strfp));
			//if(strlen(strfp) == 1)
			{
				st = atoi(strfp);
				if(st)
				{
					pclose(fp);
					debug_print(PULSE_LOG_FILE,8,"[%s] Sync with ntpserver [%s] failed..",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",ntp);
					signal(SIGCHLD, handleChildDeath);
					return 0;
				}
				else
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] Sync with ntpserver [%s] done..",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",ntp);
					pclose(fp);
					signal(SIGCHLD, handleChildDeath);
					return 1;
				}	
			}
		}	

		pclose(fp);
		signal (SIGCHLD, handleChildDeath);
		return 0;
	}

	signal (SIGCHLD, handleChildDeath);
	return 0;
}
#endif

int SyncTime(struct lvsConfig *config, int sock, int sock_priv, int *flags, 
			struct sockaddr_in *partner, struct sockaddr_in *partner_priv)
{
	struct stat st;
	//static time_t dtFileModification = 0;
	char ntp1[256] = {0};
	char ntp2[256] = {0};
	char intval[8] = {0};

	int issyncntp1alreadyattempted = 0;
	int issyncntp2alreadyattempted = 0;
	int synctried = 2;
	
	if(!stat(NTP_SERVER_CONF_FILE, &st))
	{
		//if(dtFileModification != st.st_mtime)
		//{
		//dtFileModification = st.st_mtime;

		int fd;
		fd = open(NTP_SERVER_CONF_FILE, O_RDONLY);
		if(fd >= 0)
		{
			char data[512] = {0};
			ssize_t readlen;

			readlen = read(fd,data,sizeof(data));
			if(readlen > 0)
			{
				char *token = strtok(data,"\n");
				while(token)
				{
					/*if(strstr(token,"ISNTPSYNCENABLED=1"))
					  {
					  ntpSyncEnabled = 1;						
					  }
					  else if(strstr(token,"ISNTPSYNCENABLED=0"))
					  {
					  ntpSyncEnabled = 0;						
					  }*/

					if(strstr(token,"NTPSYNCINTERVAL="))
					{
						strcpy(intval,token + strlen("NTPSYNCINTERVAL="));
						ntpInterval = atoi(intval);				
					}

					if(strstr(token,"NTP1="))
					{	
						strcpy(ntp1,token + strlen("NTP1="));
						if(strlen(ntp1))
						{
							synctried = 1;	
							if(SyncTimeWithNTPServer(ntp1, config, sock, sock_priv, flags, partner, partner_priv))
							{
								//system("echo `/usr/bin/date` > /home/fes/ntpdate_last.txt");
								return 1;
							}
							else if((issyncntp2alreadyattempted == 1))
								return 0;
							else
								issyncntp1alreadyattempted = 1;
						}
					}

					if(strstr(token,"NTP2="))
					{
						strcpy(ntp2,token + strlen("NTP2="));
						if(strlen(ntp2))
						{
							synctried = 1;
							if(SyncTimeWithNTPServer(ntp2, config, sock, sock_priv, flags, partner, partner_priv))
							{
								//system("echo `/usr/bin/date` > /home/fes/ntpdate_last.txt");
								return 1;
							}
							else if((issyncntp1alreadyattempted == 1))
								return 0;
							else
								issyncntp2alreadyattempted = 1;
						}
					}

					token = strtok(NULL,"\n");
				}

			}
			else
				return 2;
		}
		else
			return 2;
		//}
		//else
		//	return 0;
	}
	else
		return 2;
				
	return synctried;
}		
	static int
run(struct lvsConfig *config, int sock, int sock_priv, int flags)
{
	struct timeval now;
	struct timeval sendHeartBeat;
	struct timeval needHeartBeat;
	struct timeval ntpLastSyncTime;
	struct timeval timeout;
	struct timeval *smaller;
	fd_set fdset;
	int done = 0;
	int rc = 0;
	unsigned int magic;		/* beware of sign change during assignment */
	socklen_t size;		/* See page 27 of R.Stevens UNIX Net. prog. vol1 ed 2 */
	struct sockaddr_in partner, partner_priv;
	struct sockaddr_in sender;
	int use_fos = 0;
	sigset_t sigs;


	if(config->lvsServiceType == LVS_SERVICE_TYPE_FOS)
		use_fos = -1;

	sigemptyset(&sigs);
	sigaddset(&sigs, SIGINT);
	sigaddset(&sigs, SIGTERM);
	sigaddset(&sigs, SIGHUP);
	sigaddset(&sigs, SIGCHLD);
	sigaddset(&sigs, SIGALRM);

	/***** ### disable incomplete processing of USR 1 & 2 ###
	  sigaddset(&sigs, SIGUSR1);
	  sigaddset(&sigs, SIGUSR2);
	 ********************************************************/

	sigprocmask (SIG_BLOCK, &sigs, NULL);

	signal(SIGINT, handleTermSignal);
	signal(SIGTERM, handleTermSignal);
	signal(SIGALRM, handleAlarmSignal);
	signal(SIGHUP, handleHupSignal);
	signal(SIGCHLD, handleChildDeath);

	/***** ### disable incomplete processing of USR 1 & 2 ###
	  signal(SIGUSR1, handleUser1Signal);
	 ********************************************************/

	if(config->lvsServiceType == LVS_SERVICE_TYPE_FOS)
	{
		use_fos = -1;
		heartbeat_running_magic = (int) FOS_HEARTBEAT_RUNNING_MAGIC;
		heartbeat_stopped_magic = (int) FOS_HEARTBEAT_STOPPED_MAGIC;
		/* incompatible heartbeats will ensure the user doesn't mix systems */
	}

	if(use_fos == 0)
	{
		debug_print(PULSE_LOG_FILE,8,"Executing Inactive command and starting ipvs sync daemon in Backup Mode.");
		sigprocmask(SIG_UNBLOCK, &sigs, NULL);
		executeCommand(config, flags, config->inactiveCommand);
		syncDaemon(config, flags, 0);
	}

	flags |= PULSE_FLAG_SUPPRESS_ERRORS;	/* Suppress useless start errs */

	if(flags & PULSE_FLAG_AMACTIVE)
	{
		debug_print(PULSE_LOG_FILE,8,"Oh Ho! I am the active node buddy.");
		debug_print(PULSE_LOG_FILE,8,"Now Activating LVS Service. Exec'ing LVS, IPVS, SendArp Here.");
		piranha_log (flags,
				(char *) "Forced active on startup: activating lvs");
		HA_Process = activateLvs (config, flags);
	}

	flags &= (~PULSE_FLAG_SUPPRESS_ERRORS);

	debug_print(PULSE_LOG_FILE,8,"Setting HeartBeat Socket for Partner on port %d",config->heartbeatPort);
	partner.sin_family = AF_INET;
	partner.sin_port = htons (config->heartbeatPort);

	if(flags & PULSE_FLAG_AMMASTER)
	{
		PutInHALogs("I am Master configured node.");
		debug_print(PULSE_LOG_FILE,8,"I am Master, so doing heartbeat with Backup Server %s on port %d",inet_ntoa(config->backupServer),config->heartbeatPort);
		memcpy(&partner.sin_addr, &config->backupServer, sizeof (struct in_addr));
	}
	else
	{
		PutInHALogs("I am Backup configured node.");
		debug_print(PULSE_LOG_FILE,8,"I am Backup, so doing hearbeat with Primary Server %s on port %d",inet_ntoa(config->primaryServer),config->heartbeatPort);
		memcpy(&partner.sin_addr, &config->primaryServer, sizeof (struct in_addr));
	}

	if(sock_priv > -1)
	{
		debug_print(PULSE_LOG_FILE,8,"Socket private is set. So Setting heartbeat on private address also.");
		partner_priv.sin_family = AF_INET;
		partner_priv.sin_port = htons(config->heartbeatPort);
		if(flags & PULSE_FLAG_AMMASTER)
			memcpy(&partner_priv.sin_addr, &config->backupPrivate,
					sizeof (struct in_addr));
		else
			memcpy(&partner_priv.sin_addr, &config->primaryPrivate,
					sizeof (struct in_addr));
	}

	ntpInterval = DEFAULT_NTPINTERVAL;
	/*if(!SyncTime(config, sock, sock_priv, &flags, &partner, &partner_priv))
	{
		debug_print(PULSE_LOG_FILE,8,"NTP syncing failed. Default ntp sync interval is [%d].",ntpInterval);
	}*/
	
	gettimeofday(&now, NULL);
	needHeartBeat = sendHeartBeat = now;
	sendHeartBeat.tv_sec += config->keepAliveTime;
	needHeartBeat.tv_sec += config->deadTime;
	ntpLastSyncTime.tv_sec = now.tv_sec;

	debug_print(PULSE_LOG_FILE,8,"KeepAlive time is [%d] secs, DeadTime is [%d] secs.",config->keepAliveTime,config->deadTime);

	if(use_fos == 0)
	{
		sigemptyset(&sigs);
		sigaddset(&sigs, SIGCHLD);
	}
	else
	{
		debug_print(PULSE_LOG_FILE,8,"Signals unblocked, Let them come.");
		sigprocmask(SIG_UNBLOCK, &sigs, NULL);
	}

	while(!done)
	{
		gettimeofday(&now, NULL);
		if(!(flags & PULSE_FLAG_LINKFAIL))
		{	
			if((ntpLastSyncTime.tv_sec + (ntpInterval*60)) < now.tv_sec)
			{
				debug_print(PULSE_LOG_FILE,8,"[%s] NTP sync interval expired, syncing with configured NTP server.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

				if(SyncTime(config, sock, sock_priv, &flags, &partner, &partner_priv) != 2)
				{
					gettimeofday(&now, NULL);
					needHeartBeat = sendHeartBeat = now;
					sendHeartBeat.tv_sec += config->keepAliveTime;
					needHeartBeat.tv_sec += config->deadTime;
					send_heartbeat(config, sock, sock_priv, &flags,
                                                &partner, &partner_priv);
				}

				ntpLastSyncTime.tv_sec = now.tv_sec;	
			}
		}
		
		if(needHeartBeat.tv_sec < sendHeartBeat.tv_sec)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Need heartBeat is smaller in secs",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			smaller = &needHeartBeat;
		}
		else if(needHeartBeat.tv_sec > sendHeartBeat.tv_sec)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Send heartBeat is smaller in secs.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			smaller = &sendHeartBeat;
		}
		else if(needHeartBeat.tv_usec < sendHeartBeat.tv_usec)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Need heartBeat is smaller in micro secs.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			smaller = &needHeartBeat;
		}
		else
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] Send heartBeat is smaller in micro secs.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			smaller = &sendHeartBeat;
		}

		//gettimeofday(&now, NULL);
		
		
		timeout.tv_sec = -1;

		if(smaller->tv_sec >= now.tv_sec)
			timeout.tv_sec = smaller->tv_sec - now.tv_sec;

		if(smaller->tv_usec >= now.tv_usec)
			timeout.tv_usec = smaller->tv_usec - now.tv_usec;
		else
		{
			timeout.tv_usec = (smaller->tv_usec + 1000000) - now.tv_usec;
			timeout.tv_sec--;
		}

		debug_print(PULSE_LOG_FILE,8,"[%s] going in timeout for %d secs and %d micro secs.",
					(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",timeout.tv_sec,timeout.tv_usec);

		if(timeout.tv_sec >= 0)
		{
			int fds_to_process;
			int max_fd = sock;
			FD_ZERO(&fdset);
			FD_SET(sock, &fdset);

			if(sock_priv > -1)
			{
				FD_SET(sock_priv, &fdset);
				if(sock_priv > max_fd)
					max_fd = sock_priv;
			}

			if(check_links(config, &flags) == 0 && (check_link_status(config, &flags) == 0))
			{
				/* A link died. Set shutdown flag. */
				/* Check again, confirm if link is actually down*/
				PutInHALogs("Link is detected down.");
				
				debug_print(PULSE_LOG_FILE,8,"[%s] Link is detected down.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
				if(!(flags & PULSE_FLAG_LINKFAIL))
				{
					PutInHALogs("Link fail set.");
					piranha_log(flags,"Local NIC link failure: Pulse disabled");
					flags |= PULSE_FLAG_LINKFAIL;
					if(flags & PULSE_FLAG_AMACTIVE)
					{
						PutInHALogs("I was running active, so going inactive on event of link failure.");
						debug_print(PULSE_LOG_FILE,8,"[%s] Shutting down services in case of link failure.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						shutdown_services("local link failure");
					}
				}
			}
			else
			{
				if(flags & PULSE_FLAG_LINKFAIL)
				{
					/* Link up, time to be normal again */
					debug_print(PULSE_LOG_FILE,8,"[%s] Link is detected up. Checking Network connectivity.",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					if(!IsNetworkConnectivityBroken(&partner, flags))
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Recovered from down link.",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						PutInHALogs("I am recovered from link/network fail. Link is up again.");
						piranha_log(flags,
								"Local NIC link(s) restored: Pulse enabled");
						flags &= ~PULSE_FLAG_LINKFAIL;
						hearbeat_recieved_after_link_or_network_fail = 0;
						deadtimeout_expired_after_fail_cond = 0;
					}
					else
					{
						PutInHALogs("My local network is unreachable.");
						debug_print(PULSE_LOG_FILE,8,"[%s] My local network is still unreachable",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						hearbeat_recieved_after_link_or_network_fail = 0;
					}
				}
			}

			/*  There's a small race between this check and the select(), but
			    I don't know how to avoid it? */

			do
			{
				if(processSignals(config, &flags, use_fos, &sigs))
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] process signal failed.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					return 0;
				}

				if(timeout.tv_sec > 6)
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] adjusting over timeout secs.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					timeout.tv_sec = 6;
					timeout.tv_usec = 0;

					gettimeofday(&now, NULL);
                                        needHeartBeat = sendHeartBeat = now;
                                        sendHeartBeat.tv_sec += config->keepAliveTime;
                                        needHeartBeat.tv_sec += config->deadTime;

				}

				fds_to_process = select(max_fd + 1, &fdset, NULL, NULL, &timeout);
			}
			while(fds_to_process == -1 && errno == EINTR);

			if(fds_to_process < 0)
			{
				char msg[1024] = {0};
				sprintf(msg,"Pulse is exiting on select failure, error is %s",strerror(errno));
				PutInHALogs(msg);
				debug_print(PULSE_LOG_FILE,8,"[%s] select failed: %s",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strerror (errno));
				piranha_log (flags, (char *) "select() failed: %s", strerror (errno));
				return -1;

			}
			else if(fds_to_process == 0)
			{
				/* timed out, we must have something to do */
				debug_print(PULSE_LOG_FILE,8,"[%s] select timed out.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
				timeout.tv_sec = -1;
			}
			else while(fds_to_process--)
			{
				int fd_to_process;

				if (sock_priv > -1 && FD_ISSET (sock_priv, &fdset))
					fd_to_process = sock_priv;
				else if (FD_ISSET (sock, &fdset))
					fd_to_process = sock;
				else break; /* shouldn't get here */

				FD_CLR (fd_to_process, &fdset);

				size = sizeof (struct sockaddr);
				rc = recvfrom (fd_to_process, &magic, sizeof (magic), 0,
						(struct sockaddr *) &sender, &size);

				if(rc < 0)
				{
					if (errno != ECONNREFUSED)
						piranha_log (flags, (char *) "recvfrom() failed: %s", strerror (errno));
					debug_print(PULSE_LOG_FILE,8,"[%s] recvfrom() failed, error string %s",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",strerror (errno));

				}
				else if(size != sizeof (sender))
				{
					piranha_log (flags, (char *) "Bad remote address size from recvfrom");

				}
				else if(memcmp (&partner.sin_addr, &sender.sin_addr, sizeof (partner.sin_addr)) && (sock_priv == -1 ||
							memcmp (&partner_priv.sin_addr, &sender.sin_addr,
								sizeof (partner_priv.sin_addr))))
				{
					if (pulse_debug)
						piranha_log (flags, (char *) "Unexpected heartbeat from %s", inet_ntoa (sender.sin_addr));
					debug_print(PULSE_LOG_FILE,8,"[%s] Unexpected heartbeat from %s", (flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive",inet_ntoa (sender.sin_addr));

				}
				else if(rc != sizeof (magic))
				{
					piranha_log (flags, (char *) "bad heartbeat packet");
					debug_print(PULSE_LOG_FILE,8,"[%s] Read is not complete, bad heartbeat packet",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

				}
				else if((magic != heartbeat_running_magic) &&
						(magic != heartbeat_stopped_magic) &&
						(magic != FOS_HEARTBEAT_STOPME_MAGIC) &&
						(magic != HEARTBEAT_HOLD_MAGIC) &&
						(magic != HEARTBEAT_HELD_MAGIC))
				{
					piranha_log (flags, (char *) "Incompatible heartbeat received -- other system not using identical services");
					debug_print(PULSE_LOG_FILE,8,"Incompatible heartbeat received -- other system not using identical services");
				}
				else
				{
					if(!hearbeat_recieved_after_link_or_network_fail)
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Got First Heartbeat from other node after link/network recovery.",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						hearbeat_recieved_after_link_or_network_fail = 1;
						deadtimeout_expired_after_fail_cond = 1;
					}

					if(pulse_debug)
						piranha_log (flags, (char *) "DEBUG -- Received Heartbeat from partner");
					debug_print(PULSE_LOG_FILE,8,"[%s] Got Heartbeat from other node.",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

					if(magic == heartbeat_running_magic)
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Other node is running active.",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						flags &= (~PULSE_FLAG_CHILDFAIL);

						if (((flags & PULSE_FLAG_AMACTIVE) != 0) &&
								((flags & PULSE_FLAG_AMMASTER) == 0))
						{
							/* Both are running and we are backup */

							/* Send one last heartbeat to make sure
							   the master knows we were operating.  This
							   will make it re-arp its VIPs */
							debug_print(PULSE_LOG_FILE,8,"[%s] I am backup and was running active, but now going inactive.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
							send_heartbeat(config, sock, sock_priv, &flags,
									&partner, &partner_priv);
							PutInHALogs("I am backup and was running active, but now going inactive as partner is back.");
							shutdown_services("partner active");
						}
						else if ((flags & PULSE_FLAG_AMACTIVE) &&
								(flags & PULSE_FLAG_AMMASTER))
						{
							/* Both are running & we are master */
							debug_print(PULSE_LOG_FILE,8,"[%s] I am master and I am active too, but backup node is also active, which is not expected",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
							if (use_fos == 0)
							{
								piranha_log (flags, (char *) "partner active: resending arps");
								// No need to execute these commands here and we should do a sendheartbeat
								PutInHALogs("I am master and I am active too, but backup node is also active, which is not expected. Restarting my agents(info, filesync). Resending ARPS.");
								executeCommand (config, flags, config->activeCommand);
								sendLvsArps (config, flags);
							}
							else
								piranha_log (flags, (char *) "partner active");
						}
						else if(((flags & PULSE_FLAG_AMACTIVE) == 0) && (flags & PULSE_FLAG_AMMASTER))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am master and I am inactive, while backup is running active as not expected",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						}
						else if(((flags & PULSE_FLAG_AMACTIVE) == 0) && ((flags & PULSE_FLAG_AMMASTER) == 0))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am backup and running inactive as expected",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");	
						}
						else	
							debug_print(PULSE_LOG_FILE,8,"[%s] some other critical situation.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

					}
					else if(magic == heartbeat_stopped_magic)
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] Other node is running inactive.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						flags &= (~(PULSE_FLAG_FAILPARTNER |
									PULSE_FLAG_SUPPRESS_TC_MSG));

						if(((flags & PULSE_FLAG_AMACTIVE) == 0) &&
								((flags & PULSE_FLAG_AMMASTER) != 0) &&
								((flags & PULSE_FLAG_LINKFAIL) == 0) &&
								((flags & PULSE_FLAG_CHILDFAIL) == 0))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am master, I am not active. I recieved stopped command from other pulse, so restarting my lvsd services.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");

							PutInHALogs("I am master, I am not active. I recieved stopped command from other pulse, so restarting my lvsd services.");
							startup_services("backup inactive");
						}
						else if(((flags & PULSE_FLAG_AMACTIVE) != 0) && ((flags & PULSE_FLAG_AMMASTER) != 0))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am master, I am active, backup pulse is running inactive as expected",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						}

						if(((flags & PULSE_FLAG_AMACTIVE) == 0) &&
								((flags & PULSE_FLAG_AMMASTER) == 0) &&
								((flags & PULSE_FLAG_LINKFAIL) == 0) &&
								((flags & PULSE_FLAG_CHILDFAIL) == 0))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am not master, I am not active. I recieved stopped command from other pulse, so restarting my lvsd services.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
							PutInHALogs("I am not master, I am not active. I recieved stopped command from other pulse, so restarting my lvsd services.");
							startup_services("primary inactive");
						}
						else if(((flags & PULSE_FLAG_AMACTIVE) != 0) && ((flags & PULSE_FLAG_AMMASTER) == 0))
						{
							debug_print(PULSE_LOG_FILE,8,"[%s] I am backup, I am active, master pulse is running inactive, not expected",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						}
					}

					debug_print(PULSE_LOG_FILE,8,"[%s] Resetting new heartbeat time.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					gettimeofday(&needHeartBeat, NULL);
					needHeartBeat.tv_sec += config->deadTime;
				}
			}
		}

		if(timeout.tv_sec < 0)
		{
			debug_print(PULSE_LOG_FILE,8,"[%s] In send heartbeat",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			if(smaller == &sendHeartBeat)
			{
				debug_print(PULSE_LOG_FILE,8,"[%s] Send Heartbeat time is expired, sending a new heartbeat.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
				send_heartbeat(config, sock, sock_priv, &flags,
						&partner, &partner_priv);

				gettimeofday(&sendHeartBeat, NULL);
				sendHeartBeat.tv_sec += config->keepAliveTime;

			}
			else /* smaller != &... */
			{
				if((hearbeat_recieved_after_link_or_network_fail == 0) && (deadtimeout_expired_after_fail_cond == 0))
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] This is the first time i have get here. Waiting for next no beat",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					deadtimeout_expired_after_fail_cond = 1;
				}
				else if(hearbeat_recieved_after_link_or_network_fail == 0)
				{
					debug_print(PULSE_LOG_FILE,8,"[%s] Still no heartbeat after deadtimeout expiry",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						hearbeat_recieved_after_link_or_network_fail = 1;
						deadtimeout_expired_after_fail_cond = 1;
				}
				
				debug_print(PULSE_LOG_FILE,8,"[%s] recieved no heartbeat from partner, assuming him dead.",
						(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
				if (!(flags & PULSE_FLAG_AMACTIVE) &&
						!(flags & PULSE_FLAG_LINKFAIL) &&
						!(flags & PULSE_FLAG_CHILDFAIL) && (hearbeat_recieved_after_link_or_network_fail))
				{
					if(!IsNetworkConnectivityBroken(&partner, flags))
					{
						piranha_log(flags,(char *) "partner dead: activating lvs");
						debug_print(PULSE_LOG_FILE,8,"[%s] partner is dead, becoming active.",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						//debug_print(PULSE_LOG_FILE,8,"");
						PutInHALogs("I was not active. I am activating LVS and becoming active as Partner is detected dead");
						HA_Process = activateLvs (config, flags);
						flags |= PULSE_FLAG_AMACTIVE;
					}
					else
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] My network is unreachable, means i am out of network",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						flags |= PULSE_FLAG_LINKFAIL;

						if(flags & PULSE_FLAG_AMACTIVE)
						{
							PutInHALogs("I was running active, now going inactive on event of network unreachability.");
							debug_print(PULSE_LOG_FILE,8,"[%s] Shutting down services in case of link failure.",
									(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
							shutdown_services("local network unreachable.");
						}

						hearbeat_recieved_after_link_or_network_fail = 0;
						deadtimeout_expired_after_fail_cond = 0;
					}
				}
				else if(!(flags & PULSE_FLAG_LINKFAIL))
				{
					/* Partner is dead, and we are already active */
					flags &= (~(PULSE_FLAG_SUPPRESS_TC_MSG | PULSE_FLAG_FAILPARTNER));
					debug_print(PULSE_LOG_FILE,8,"[%s] Partner is found unreachable.",
							(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
					if(IsNetworkConnectivityBroken(&partner, flags))
					{
						debug_print(PULSE_LOG_FILE,8,"[%s] My network is unreachable, means i am out of network",
								(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
						flags |= PULSE_FLAG_LINKFAIL;

						if(flags & PULSE_FLAG_AMACTIVE)
						{
							PutInHALogs("I was running active, so going inactive on event of link failure.");
							debug_print(PULSE_LOG_FILE,8,"[%s] Shutting down services in case of link failure.",
									(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
							shutdown_services("local network unreachable.");
						}

						hearbeat_recieved_after_link_or_network_fail = 0;
						deadtimeout_expired_after_fail_cond = 0;
					}	
				}
				
				gettimeofday (&needHeartBeat, NULL);
				needHeartBeat.tv_sec += config->deadTime;
				debug_print(PULSE_LOG_FILE,8,"[%s] Reset new need heartbeat time.",(flags & PULSE_FLAG_AMACTIVE)?"Active":"Inactive");
			} /* else (smaller != ... ) */
		}
	}

	debug_print(PULSE_LOG_FILE,8,"Pulse Exiting, Bye!");
	return 0;
}


/*
 **  amMaster() --   Determine if we are primary or backup node.
 */

	static int
amMaster (struct lvsConfig *config, int flags)
{

	FILE *fp;
	int res = 0;
	char buf[1024];
	char *start, *end;
	int s = socket (AF_INET, SOCK_DGRAM, 0);
	struct in_addr addr;

	if ((fp = fopen ("/proc/net/dev", "r")) == NULL)
	{
		piranha_log (flags, (char *) "failed to open /proc/net/dev!\n");
		close (s);
		return 1;
	}

	while (fgets(buf, sizeof(buf), fp))
	{
		for (start = buf; isspace(*start); start++);
		end = strchr (start, ':');
		if (!end)
			continue;
		*end = '\0';

		if (!getInterfaceAddress (s, start, &addr, flags) &&
				!memcmp (&addr, &config->primaryServer, sizeof (addr)))
		{
			res = 1;
			break;
		}
	}

	close(s);
	fclose(fp);

	return res;
}

int get_process_name(const pid_t pid, char* name) 
{
	char procfile[1024] = {0};
	
	sprintf(procfile, "/proc/%d/cmdline", pid);
	FILE* f = fopen(procfile, "r");
	if(f) 
	{
		size_t size;
		size = fread(name, sizeof (char), sizeof (procfile), f);
		if(size > 0) 
		{
			if ('\n' == name[size - 1])
				name[size - 1] = '\0';
		}
		else
			return 0;
		
		fclose(f);
	}
	else
		return 0;

	return 1;
}

void printparentprocessname()
{
	char parentname[256] = {0};
	pid_t myppid = getppid();
	if(myppid != -1)
	{
		if(get_process_name(myppid, parentname))
		{
			char log[512] = {0};
			sprintf(log, "pulse parent process name %s", parentname);
			PutInHALogs(log);
		}
	}
}
	int
main (int argc, const char *argv[], char *env[])
{
	int noDaemon = 0;
	int flags = 0;
	int rc = 0;
	int fd, fd_priv;
	int line;
	struct lvsConfig config;
	int master = 0;
	int noRun = 0;
	int teststart = 0;
	int forceActive = 0;
	poptContext optCon;
	//char *fargv[40];
	int i;
	int service_count = 0;
	int display_ver = 0;

	debug_print(PULSE_LOG_FILE,8,"Pulse Started.");
	PutInHALogs("Pulse getting started.");
	printparentprocessname();

	struct poptOption options[] = {

		{"configfile", 'c', POPT_ARG_STRING, &configFile, 0,
			N_("Configuration file"), N_("configfile")},

		{"nodaemon", 'n', 0, &noDaemon, 0,
			N_("Don't run as a daemon")},

		{"test-start", 't', 0, &teststart, 0,
			N_("Don't actually run lvs or fos")},

		{"verbose", 'v', 0, &pulse_debug, 0,
			N_("Display debugging information")},

		{"forceactive", '\0', 0, &forceActive, 0,
			N_("Force into the active state")},

		{"lvsd", '\0', POPT_ARG_STRING, &lvsBinary, 0,
			N_("Location of lvs binary (defaults /usr/sbin/lvsd)")},

		{"fos", '\0', POPT_ARG_STRING, &fosBinary, 0,
			N_("Location of fos binary (defaults /usr/sbin/fos)")},

		{"norun", '\0', 0, &noRun, 0,
			N_("Same as 'test-start'")},

		{"version", '\0', 0, &display_ver, 0,
			N_("Display program version")},

		POPT_AUTOHELP

			POPT_TABLEEND

	};


	optCon = poptGetContext ("pulse", argc, argv, options, 0);
	poptReadDefaultConfig (optCon, 1);

	if ((rc = poptGetNextOpt (optCon)) < -1)
	{
		fprintf (stderr, _("pulse: bad argument %s: %s\n"),
				poptBadOption (optCon, POPT_BADOPTION_NOALIAS),
				poptStrerror (rc));
		return 1;
	}

	if (poptGetArg (optCon))
	{
		fprintf (stderr, _("pulse: unexpected arguments\n"));
		return 1;
	}

	poptFreeContext (optCon);
	logName ((char *) "pulse");

	if (display_ver)
	{
		printf ("Program Version:\t%s\n", _PROGRAM_VERSION);
		printf ("Built:\t\t\t%s\n", DATE);	/* DATE epulled from Makefile */
		printf ("A component of:\t\tpiranha-%s-%s\n", VERSION, RELEASE);
		return 0;
	}


	if (noDaemon)
	{
		debug_print(PULSE_LOG_FILE,8,"Running in no daemon mode.");
		flags |= LVS_FLAG_PRINTF;
	}
	else
	{
		debug_print(PULSE_LOG_FILE,8,"Running in daemon mode.");
		flags |= PULSE_FLAG_ASDAEMON | LVS_FLAG_SYSLOG;
	}

	if (forceActive)
	{
		debug_print(PULSE_LOG_FILE,8,"I am Forced Active.");
		flags |= PULSE_FLAG_AMACTIVE;
	}

	if (noRun | teststart)
	{
		debug_print(PULSE_LOG_FILE,8,"I am just a test run.");
		flags |= PULSE_FLAG_NORUN;
	}

	if ((fd = open (configFile, O_RDONLY)) < 0)
	{
		debug_print(PULSE_LOG_FILE,8,"Failed to open config file.");
		fprintf (stderr, "pulse: failed to open %s\n", configFile);
		return 1;
	}

	if ((rc = lvsParseConfig (fd, &config, &line)))
	{
		debug_print(PULSE_LOG_FILE,8,"LvsParseConfig Error: error parsing %s at line %d: %s",configFile,line,lvsStrerror(rc));
		fprintf (stderr, "pulse: error parsing %s at line %d: %s\n",
				configFile,line,lvsStrerror(rc));
		return 1;
	}

	debug_print(PULSE_LOG_FILE,8,"LvsParseConfig returned %d",rc);
	lvsRelocateFS (&config);
	/* Move failover services and Clean up virtual server list */

	close (fd);

	master = amMaster (&config, flags);
	flags |= master ? PULSE_FLAG_AMMASTER : 0;

	if(master)
	{
		debug_print(PULSE_LOG_FILE,8,"I am MASTER node.");
	}

	if(config.backupActive)
	{
		debug_print(PULSE_LOG_FILE,8,"config.backupActive is 1");
		if (config.backupServer.s_addr == 0)
		{
			config.backupActive = 0;
			piranha_log (flags,
					(char *)
					"Undefined backup node marked as active? -- clearing that!");
		}
	}


	if(!rc)
	{
		if (config.lvsServiceType == LVS_SERVICE_TYPE_FOS)
		{
			for (i = 0; i < config.numFailoverServices; ++i)
			{
				if (config.failoverServices[i].isActive)
					++service_count;
			}

			if (!service_count)
			{
				fprintf (stderr,
						"pulse: no active fos services defined in %s\n",
						configFile);
				return 1;
			}
		}
		else
		{
			debug_print(PULSE_LOG_FILE,8,"I am configured only to run LVS service.");
			for (i = 0; i < config.numVirtServers; ++i)
			{
				if (config.virtServers[i].isActive)
					++service_count;
			}
			if (!service_count)
			{
				fprintf (stderr,
						"pulse: no active lvs services defined in %s\n",
						configFile);
				debug_print(PULSE_LOG_FILE,8,"No active services, Exiting.");
				return 1;
			}
		}
	}
	else
		debug_print(PULSE_LOG_FILE,8,"Parsing LVS is failed i guess.");


	if ((fd = createSocket (master ? &config.primaryServer : &config.backupServer, config.heartbeatPort, flags)) < 0)
	{
		fprintf (stderr, "pulse: cannot create heartbeat socket. running as root?\n");
		debug_print(PULSE_LOG_FILE,8,"createSocket failed.");
		return 1;
	}

	debug_print(PULSE_LOG_FILE,8,"Primary Server %s, Primary Private %s",inet_ntoa(config.primaryServer), inet_ntoa(config.primaryPrivate));
	if (memcmp (&config.primaryServer, &config.primaryPrivate,sizeof (config.primaryServer))) 
	{
		if ((fd_priv = createSocket (master ? &config.primaryPrivate :
						&config.backupPrivate, config.heartbeatPort,
						flags)) < 0)
		{
			fprintf (stderr, "pulse: cannot create heartbeat socket. "
					"running as root?\n");
			debug_print(PULSE_LOG_FILE,8,"createSocket failed for primary private.");
			return 1;
		}
	}
	else
		fd_priv = -1;

	if (flags & PULSE_FLAG_ASDAEMON)
	{
		debug_print(PULSE_LOG_FILE,8,"Now daemonizing.");
		if (daemonize (flags))
		{
			debug_print(PULSE_LOG_FILE,8,"Parent Exiting.");
			exit (0);
		}
	}

	if (flags & LVS_FLAG_SYSLOG)
	{
		openlog ("pulse", LOG_PID, LOG_DAEMON);
	}

	if (master)
	{
		piranha_log (flags, (char *) "STARTING PULSE AS MASTER");
		debug_print(PULSE_LOG_FILE,8,"Starting as Master Node.");
		if (!config.backupActive)
		{
			if ((config.lvsServiceType == LVS_SERVICE_TYPE_FOS) &&
					(forceActive == 0))
			{
				piranha_log (flags,
						(char *)
						"Warning: FOS backup node not defined -- skipping checks");
				flags |= PULSE_FLAG_AMACTIVE;
			}
		}

	}
	else if (!config.backupActive)
	{
		piranha_log (flags,
				(char *)
				"We are backup node and backup is marked inactive -- exiting pulse");
		rc = -1;
	}
	else
	{
		debug_print(PULSE_LOG_FILE,8,"Starting as backup Node.");
		piranha_log (flags, (char *) "STARTING PULSE AS BACKUP");
	}	


	if (!rc)
		rc = run (&config, fd, fd_priv, flags);

	if (flags & PULSE_FLAG_ASDAEMON)
		unlink ("/var/run/pulse.pid");

	PutInHALogs("Pulse service exiting.");	
	debug_print(PULSE_LOG_FILE,8,"Pulse exiting.");	
	return rc;
}
