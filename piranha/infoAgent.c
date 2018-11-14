#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <signal.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
//#include <net/netopt.h>
#include <netinet/tcp.h>
#include <sys/ioctl.h>
#include <linux/sockios.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/queue.h>
#include <asm/socket.h>
#include <errno.h>
#include <pthread.h>
#include "lvsconfig.h"
#include <stdbool.h>
#include <sys/file.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <poll.h>
#include <pthread.h>
//#include </root/hygateway/include/debug.h>
#include <errno.h>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>
/****************************************************************************************
  infoagent wil be started on active and passive load balancer by the  
  pulse agent it self.In case of Failover handling this agent will be restarted.

  For real server (VPN Gateway), this will be by deafult running in as the background 
  process.
 ****************************************************************************************/

#define INFOAGENT_CONNECT_TIMEOUT			5
#define MAX_RETRY_TO_RESTART_INFOAGENT			10
#define INFOAGENT_KILL_RETRY_ATTEMTPS			10
#define RESTART_YOUR_PULSE_IF_BACKUP			0x02
#define PASSIVE_INFO_SENDING_NODE_STATUS		0x04
#define STATUS_RESPONSE_REQ_CGI				0x81
#define INFOAGENT_LOG_FILE				"/home/fes/logs/infoagent.log"
#define HA_COMMON_LOGS					"/home/fes/logs/ha.log"
#define FILES_TO_SYNC					"/home/fes/filestosync"
#define MAX_FILE_LENGTH					256

#define DEBUG_INFO					1
#define	DEBUG_ERROR					2 
#define CNF_FILE 					"/etc/sysconfig/ha/lvs.cf"
#define CNFSCRIPT_FILE 					"/etc/sysconfig/ha/getactive.sh"
#define UDPAGENTPORT 					939
#define MAX_NUMBER_OF_REAL_SERVERS 			12
#define ifaddr(x) 					(*(struct in_addr *) &x->ifr_addr.sa_data[sizeof sa.sin_port])
#define SHMKEY_NODEINFO 				((key_t)8989)

#define SYNC_TIME 					"SYNC_TIME"

#define PULSE_RUNNING 					2
#define FILESYNC_DAEMON_RUNNING 			4
#define VPN_SERVER_RUNNING 				8
#define NTP_SERVICES_RUNNING 				16

#define SET_SOCKET_BLOCKING 				1
#define SET_SOCKET_NONBLOCKING 				0
#define INFOAGENT_SERVICE_PORT 				939
#define INFOAGENT_SERVICE_TIMEOUT_FOR_CONNECTION 	2*60 
#define MAX_NUMBER_OF_REAL_SERVERS 			12
#define FILESYNC_CONFIGURATION_FILE 			"/home/fes/filesync.conf"
#define FILESYNC_DAEMON_RESTART				"FILESYNC_RESTART" 
#define MAX_LISTEN_BACKLOG_LIMIT 			12
#define REAL_VPN_SERVER 				2
#define FES_SERVER_RESTART 				"FES_RESTART"
#define APACHE_SERVER_RESTART 				"HTTPD_RESTART"
#define PULSE_RESTART 					"PULSE_RESTART"
#define STANDBY_LOAD_BALANCER 				1
#define STANDBY_LOAB_BALANCER_AND_VPN_SERVER 		3
#define PULSE_SERVICE_RESTART 				"PULSE_RESTART"
#define ACTIVE_LOAD_BALANCER 				0
#define COMMAND_DAEMON_PIPE_NAME 			"/home/fes/commandDaemon.pipe"
#define VIP_FEATURE_STATUS_FILE 			"/home/fes/vip_feature_Status.txt"
#define START_VIP_SERV_DAEMON 				"START_VIP_SERV_DAEMON"
#define STOP_VIP_SERV_DAEMON 				"STOP_VIP_SERV_DAEMON"
#define INFOAGENT_HEARTBEAT_INTERVAL			15
#define INFOAGENT_LOCK_FILE 				"infoagent.lock"
#define INFOAGENT_PID_FILE 				"infoagent.pid"

#define IPADRRESS_MAX_LEN 				32

#define BACKUP_ACTIVE					1
#define NO_BACKUP_STATUS				2
#define BACKUP_DOWN					0

//#define ADD_INTO_REMOTE_LIST_OF_CONFIGURATION(tmpptr) TAILQ_INSERT_TAIL(&RemoteList,tmpptr,entries)
#define NTP_SERVER_CONF_FILE            		"/home/fes/ntpserver.conf"
#define DEFAULT_NTPINTERVAL             		30
#define HA_UPGRADE_MODE_STATUS_FILE                     "/tmp/hamaintaincemodefile"

#define DEBUG_LEVEL 0xffff
#define LINE_DEBUG  0

#define DEBUG_PRINT

#ifdef DEBUG_PRINT
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

#else
        #define debug_print(filename, level, fmt, args...) ;
#endif

#define NUM_FILES_LIST              128

static char filestosync[NUM_FILES_LIST][64];

static int ntpInterval = 0;
extern const char *__progname;
static volatile int g_CondVar = 0;
static  int g_NumNodes = 0;
//static int lockFd = -1;
static int shmSem = 0;
int getcmdvals(char *cmdstr,char* outstr,int bytesToRead);
bool HandleHostedVirtualIPs();
int SendData(int s, char *data, int len);
static int ListenAgentSock = 0;
bool primaryActive = false;
bool primaryInActive = false;
bool backupInActive = false;
bool backupActive = false;
static short wait_ticks = 8; /*Number of times backup node will skip active message.*/

void HandleSigTerm(int sigNum);
void getTimeZoneDetails(char *zonename);
bool SetbackupNodeStatus(short status);

#pragma pack(1)
typedef struct RealServers
{
	char IPaddress[IPADRRESS_MAX_LEN];
	int type;
	char IntfName[8];
	int SyncState;
	int num_realservers;
	short isbackupActive;
	char ActiveIPAddress[IPADRRESS_MAX_LEN];
	char BackupIPAddress[IPADRRESS_MAX_LEN];
	char VirtualIPAddress[IPADRRESS_MAX_LEN];
	char RealServer[MAX_NUMBER_OF_REAL_SERVERS*40];

}REALSERVER;
#pragma pack()

enum commandval{
	STARTSERVICE=1,
	STOPSERVICE,
	RELOADSERVICE,
	REMOTE_STATUS,
	FES_RESTART,
	RESP_STARTSERVICE=20,
	RESP_STOPSERVICE,
	RESP_RELOADSERVICE,
	RESP_FESRESTART,
	RESP_IGNORED=0,
	RESP_RESEND=41
};

typedef struct serviceCommand{
	int service;
	int command;
	int relay;
}CONFCOMMAND;

typedef struct ActiveLBData{

	char ActivePrivateIP[IPADRRESS_MAX_LEN];
	char BackupPrivateIP[IPADRRESS_MAX_LEN];
	char primaryIP[IPADRRESS_MAX_LEN];
	char backupIP[IPADRRESS_MAX_LEN];
	char ClusterVirtualIP[IPADRRESS_MAX_LEN];
	int RealServerCount;
	int num_realservers;
	char IntfName[8];
	char RealServer[MAX_NUMBER_OF_REAL_SERVERS*40];
	char current_time[128];
	char zonename[256]; 
}CONFIG_DATA;

pthread_t activeListener;

typedef struct ConfSharedStruct
{

	unsigned char SharedHash[32];
	char ResourceIP[IPADRRESS_MAX_LEN];
	char HostIP[IPADRRESS_MAX_LEN];//self Ip
	int NodeType;

}CONF_STRUCT;

struct __statusNode {

	int  NodeType;
	int  status_bit;
	char nodeIP[IPADRRESS_MAX_LEN];
	char cpu[10];
	char mem[10];
	char secMem[10];
	char sysUpTime[24];
}__attribute__((__packed__));

typedef  struct __statusNode STATUSNODE;

struct serversList
{
	char IpAddress[IPADRRESS_MAX_LEN];
	TAILQ_ENTRY(serversList) entries;
};
////////////////////////////////////////////////////FUNCTION DECLARATIONS //////////////////////////
bool FillNodeInfoIntoSharedMemory(REALSERVER *SelfSharedInfo);
bool LaunchFileSyncDaemon();
bool StartListner();
bool SendCommandToDaemon(char *command);
bool IFIamPrimaryNodeRunningInactive();
bool UpdateNodeInfoSharedMemory(CONFIG_DATA* ClusterInfo);

///////////////////////////////////////////////////////////////////////////////////////////////////
pthread_mutex_t g_NodesStatPtr_mutex;

STATUSNODE* g_NodesStatPtr = NULL;

struct sembuf lsem_lock = {0, -1, SEM_UNDO};
struct sembuf lsem_unlock = {0, 1, SEM_UNDO};

int sem_get_lock(int sid)
{
	return (semop(sid, &lsem_lock, 1));
}

int sem_set_unlock(int sid)
{
	return (semop(sid, &lsem_unlock, 1));
}

#if 0
int TestFileOpen()
{
	FILE* vfp = NULL;
	vfp = fopen(VIP_FEATURE_STATUS_FILE,"r");
		
	FILE* fp = fopen(INFOAGENT_LOG_FILE, "ab+");
	if(fp)
	{
		FILE* fp2 = fopen(INFOAGENT_LOG_FILE, "ab+");
		if(fp2)
		{
			FILE* fp3 = fopen(INFOAGENT_LOG_FILE, "ab+");
                	if(fp3)
                	{
				fprintf(fp3,"File open success. Wrote one line");
                        	fclose(fp3);
			}
			fprintf(fp2,"File open success. Wrote one line");
			fclose(fp2);
		}

		fprintf(fp,"File open success. Wrote one line");
		fclose(fp);
	}
	
	if(vfp)
		fclose(vfp);	
	
}
#endif

int create_sem()
{
	union semun {
		int      val;
		struct semid_ds *buf;
		ushort    *array;
	} semctl_arg;

	int semid;
	system ("ipcrm -S 0x0f8d8989 > /dev/null 2>&1");
	semid = semget(0x0f8d8989,1,IPC_CREAT|IPC_EXCL|0660);
	if(semid != -1)
	{
		semctl_arg.val = 1;
		if(semctl(semid,0,SETVAL,semctl_arg)< 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeSemaPhore Failed.");
			semctl(semid,1,IPC_RMID,0);
			return -1;
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeSemaPhore Failed, Checking For Existing One.");
		if(errno == EEXIST)
		{
			semid = semget(0x0f8d8989,1,IPC_CREAT|0660);
			semctl(semid,1,IPC_RMID,0);
			semid = semget(0x0f8d8989,1,IPC_CREAT|IPC_EXCL|0660);
			if(semid != -1)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeSemaPhore Created Successfully after Deleting Existing.");
				semctl_arg.val = 1;
				if(semctl(semid,0,SETVAL,semctl_arg)< 0)
				{
					semctl(semid,1,IPC_RMID,0);
					return -1;
				}
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeSemaPhore Failed,Error No %d",errno);
			return -1;
		}					
	}
	
	return semid;
}

TAILQ_HEAD(tailqhead, serversList) RemoteList;
TAILQ_HEAD(tailqhead1, serversList) LocalList;

void setsocknonblocking(int sockfd)
{
	int flags = fcntl(sockfd,F_GETFL,0);
        flags |= O_NONBLOCK;
        fcntl(sockfd, F_SETFL, flags);
}

void setsockblocking(int sockfd)
{
	int flags = fcntl(sockfd,F_GETFL,0);
        flags &= ~O_NONBLOCK;
        fcntl(sockfd, F_SETFL, flags);
}

int getcmdvals(char *cmdstr,char* outstr,int bytesToRead)
{
	FILE* fp;
	int readBytes = -1;	
	//debug_print(INFOAGENT_LOG_FILE,8,"Opening Pipe To Run Command %s",cmdstr);
	fp = popen(cmdstr,"r");
	if(fp != NULL)
	{
		readBytes = fread(outstr,sizeof(char),bytesToRead,fp);
		if(readBytes <= 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Error Occured While Reading Command Output.");
			pclose(fp);
			return 1;
		}
		outstr[readBytes] = '\0';
		pclose(fp);
		return 0;
	}
	return 1;
}

void PutRestartRequestInHALogs(char *msg)
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

//false to Non-block
int setSockBlockNonBlock(int sock,int isNonBlock)
{
	long arg;

	if((arg=fcntl(sock,F_GETFL,NULL)) < 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Get Socket Flags Failed.");
		return -1;
	}
	if(!isNonBlock)
	{
		arg = arg | O_NONBLOCK;
		if(fcntl(sock,F_SETFL,arg)<0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Set Socket Non Blocking Failed.");
			return -1;
		}
	}
	else
	{
		arg = arg & (~O_NONBLOCK);
		if(fcntl(sock,F_SETFL,arg) < 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Set Socket Blocking Failed.");
			return -1;
		}
	}
	return sock;
}

int RecvData(int sockfd,char *buffer,int rbuff_size,int *data_len)
{
	struct pollfd pfd;

	pfd.fd = sockfd;
	pfd.revents = 0;
	pfd.events = POLLIN|POLLHUP;

	*data_len = 0;
	int read_len = 0;
	int sCount;	
	int to = 2*60*1000;

	setsocknonblocking(sockfd);
	while(1)
	{
		sCount = poll(&pfd, 1, to);
		if(sCount == -1)
                {
                        if((errno == EINTR) || (errno == EAGAIN))
                        {
                                pfd.revents = 0;
				if(g_CondVar == 1)
					return 0;
                                continue;
                        }

			debug_print(INFOAGENT_LOG_FILE,8,"POll error %s",strerror(errno));
                        break;
                }
                else if(sCount == 0)
                {
			debug_print(INFOAGENT_LOG_FILE,8,"Poll Timedout after 2 idle mins, No response from other node.");
                        break;
                }

                if((pfd.revents & POLLHUP) || (pfd.revents & POLLERR))
                {
			debug_print(INFOAGENT_LOG_FILE,8,"POLLHUP or POLLERR on socket.");
                        break;
                }
readagain:		
		read_len = recv(sockfd,buffer+read_len,rbuff_size,0);
		if(read_len == 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Peer End Closed Connection.");
			*data_len = 0;
			break;
		}
		else if(read_len < 0)
		{
			if((errno != EINTR) && (errno != EAGAIN) && (errno != EWOULDBLOCK))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Peer End Read Failed Errno %d ErrString %s",errno,strerror(errno));
                        	*data_len = -1;
                        	break;
			}
			else
			{
				if(g_CondVar == 1)
                                        return 0;	
				//continue;
				goto readagain;
			}
		}
		else
			break;
	}

	//debug_print(INFOAGENT_LOG_FILE,8,"Read bytes %d",read_len);	
	*data_len = read_len;
	setsockblocking(sockfd);	
	return *data_len;
}

bool IsFilesToSyncRead()
{
        FILE *fp = NULL;
	int i = 0;
        char *line = NULL;
        size_t len = 0;

        fp = fopen(FILES_TO_SYNC, "r");

        if(!fp)
        {
		debug_print(INFOAGENT_LOG_FILE, 4, "Failed to open filestosync file.");
                return false;
	}

	memset(filestosync, 0, sizeof(filestosync));

	while(!feof(fp))
	{
		if(i < NUM_FILES_LIST)
		{
			if(getline(&line, &len , fp) != -1)
			{
				if(line && (strlen(line) > 0) && line[0] != '\n')
				{
					int filesLength = strlen(line);

					if(line[strlen(line)- 1] == '\n')
						line[strlen(line)- 1] = '\0';

					debug_print(INFOAGENT_LOG_FILE, 4, "File is %s", line);

					if(filesLength < MAX_FILE_LENGTH)
					{
						strncpy(filestosync[i], line, MAX_FILE_LENGTH);
						debug_print(INFOAGENT_LOG_FILE, 4, "Value of filestosync[%d] is %s and length is %d",
								i, filestosync[i], strlen(filestosync[i]));
					}
					else
					{

						debug_print(INFOAGENT_LOG_FILE, 4, "File length exceeds the maximum limit of %d characters.",
								MAX_FILE_LENGTH);
						debug_print(INFOAGENT_LOG_FILE, 4, "File length is %d", filesLength);
					}

					i++;
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE, 4, "Failed to read the line from the file.");
				}

			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE, 4, "No line to read in the file.");
				break;
			}
		}
		else
		{
			 debug_print(INFOAGENT_LOG_FILE, 4, "Maximum limit of %d is reached to read the line.", NUM_FILES_LIST);
		}

        }

        if(line)
        {
                debug_print(INFOAGENT_LOG_FILE, 4, "Going to free Memory !!!");
                free(line);
        }
        fclose(fp);

        return true;
}

#if 1
void WriteSynConfFile(char *serverList)
{
	int i = 0;
	char fileStr[4096] = {0};
	char command[5012] = {0};

	debug_print(INFOAGENT_LOG_FILE,8,"Updating FileSync Configuration File.");

	strcpy(fileStr,"FILES=");

	if(IsFilesToSyncRead())
	{
		for(i=0; i < NUM_FILES_LIST; i++)
		{
			if(filestosync[i] && (strlen(filestosync[i]) > 0))
			{
				strcat(fileStr,filestosync[i]);
				if(i != NUM_FILES_LIST-1)
					strcat(fileStr,",");
			}
		}
	}
	else
	{
		/* Backup if above fails */
		char files[41][256] = {"/etc/sysconfig/ha/lvs.cf",
			"/home/fes/fescommon/",
			"/home/fes/mysqldump/",
			"/var/lib/mysql/mysql/",
			"/home/fes/public/portal/realms/default/images/",
			"/home/fes/public/portal/act/apptab.html",
			"/home/fes/public/portal/act/loginPage.htm",
			"/home/fes/public/portal/act/logoutclient.html",
			"/etc/httpd/conf/httpd.conf",
			"/etc/logrotate.d/ves",
			"/home/fes/public/verinfo.js",
			"/home/fes/public/tseclientinfo.js",
			"/home/fes/.byPassSiteList",
			"/home/fes/localmail.txt",
			"/home/fes/csrmail.txt",
			"/home/fes/resetpassmail.txt",
			"/home/fes/ntp_command",
			"/home/fes/smsconf.settings",
			"/home/fes/syslog.properties",
			"/home/fes/syslog.conf",
			"/home/fes/vip_feature_Status.txt",
			"/home/fes/features.status",
			"/usr/local/bin/SparkGateway/license",
			"/usr/local/bin/SparkGateway/licenseInfo.txt",
			"/home/fes/public/portal/all/images/",
			"/home/fes/logs/MaxConcurrentUsers",
			"/home/fes/monitor.conf",
			"/home/fes/backup.conf",
			"/home/fes/public/NVPNClientSetup.exe",
			"/home/fes/public/VPNClientSetup.exe",
			"/home/fes/public/vcupgrade.zip",
			"/home/fes/public/Accops_HyWorksOndemand.exe",
			"/home/fes/public/Accops_HyWorksSetup.exe",
			"/home/fes/public/Accops_HyWorksSetup_with_SEP.exe",
			"/home/fes/public/portal/realms/default/css/customer.css",
			"/home/fes/public/customerbanner.bmp",
			"/home/fes/public/customerlogo.bmp",
			"/home/fes/public/AccopsNativeClientHost.exe",
			"/home/fes/zeroMQ.conf",
			"/home/fes/accesscontrol.ini",
			"/home/fes/fescommon/auth.xml"
		};


		sprintf(fileStr,"FILES=%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s",&files[0][0],&files[1][0],&files[2][0],&files[3][0],&files[4][0],&files[5][0],&files[6][0],&files[7][0],&files[8][0],&files[9][0],&files[10][0],&files[11][0],&files[12][0],&files[13][0],&files[14][0],&files[15][0],&files[16][0],&files[17][0],&files[18][0],&files[19][0],&files[20][0],&files[21][0],&files[22][0],&files[23][0],&files[24][0],&files[25][0],&files[26][0],&files[27][0],&files[28][0],&files[29][0],&files[30][0],&files[31][0],&files[32][0],&files[33][0],&files[34][0],&files[35][0],&files[36][0],&files[37][0], &files[38][0], &files[39][0], &files[40][0]);

	}

	debug_print(INFOAGENT_LOG_FILE,8,"Files Added For Sync %s",fileStr);
	
	sprintf(command,"echo \"%s\" > /home/fes/filesync.conf",fileStr);
	system(command);

	debug_print(INFOAGENT_LOG_FILE,8,"Real Servers Added For Sync %s",serverList);

	sprintf(command,"echo \"%s\" >> /home/fes/filesync.conf",serverList);
	system(command);

	debug_print(INFOAGENT_LOG_FILE,8,"After Updating Config file");

	while(serverList[i])
	{
		if(serverList[i] == 44)
			serverList[i] = 32;
		i++;
	}
}
#endif

bool FillLocalClusterConf()
{
	char parseCMDServer[] = "cat /home/fes/filesync.conf |awk -F = 'BEGIN{OUTPUTSTR=0;} {if($1 == MATCHSTR ){OUTPUTSTR=$2}} END{print OUTPUTSTR}' MATCHSTR=\"SERVERS\" 2>&1";
	char resultStr[MAX_NUMBER_OF_REAL_SERVERS*40] = {0};
	char *tmptok = NULL;	

	if(!getcmdvals(parseCMDServer,resultStr,MAX_NUMBER_OF_REAL_SERVERS*40))
	{
		if(strstr(resultStr,"cannot open file")!=NULL)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"FillLocalClusterConf: Error in opening filesync config file");
			return false;
		}
		else
		{
			tmptok = strtok(resultStr,",");
			
			do{
				struct serversList* tmpptr = (struct serversList*)malloc(sizeof( struct serversList));
				if(tmpptr != NULL)
				{
					memset(tmpptr, 0, sizeof(struct serversList));
					sprintf(tmpptr->IpAddress,"%s",tmptok);

					if(tmpptr->IpAddress[strlen(tmpptr->IpAddress)-1] == '\n')
						tmpptr->IpAddress[strlen(tmpptr->IpAddress)-1] = '\0';
					if(tmpptr->IpAddress[strlen(tmpptr->IpAddress)] == 0)
						tmpptr->IpAddress[strlen(tmpptr->IpAddress)] = '\0';

					//debug_print(INFOAGENT_LOG_FILE,8,"entry added to local list as %s", tmpptr->IpAddress);
					TAILQ_INSERT_TAIL(&LocalList, tmpptr, entries);
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"FillLocalClusterConf :Failed To allocate Memory.");
					return false;
				}

				tmptok = strtok(NULL,",");

			} while(tmptok != NULL);	
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"FillLocalClusterConf :Failed To run Command To Parse filesync.conf.");
		return false;
	}
	
	return true;		
}

bool CompareClusterConf(int *updateConfigFile)
{
	struct serversList* tmpptrI = NULL;
	struct serversList* tmpptrJ = NULL;
	struct serversList* tmpptrvalI = NULL;
	struct serversList* tmpptrvalJ = NULL;
/*
	for(tmpptrI = TAILQ_FIRST(&RemoteList); tmpptrI != NULL; tmpptrI = tmpptrvalI)
	{
		tmpptrvalI = TAILQ_NEXT(tmpptrI, entries);

		for(tmpptrJ = TAILQ_FIRST(&LocalList); tmpptrJ != NULL; tmpptrJ = tmpptrvalJ)
		{
			tmpptrvalJ = TAILQ_NEXT(tmpptrJ, entries);
			if(strcmp(tmpptrI->IpAddress, tmpptrJ->IpAddress) == 0)
			{
				//debug_print(INFOAGENT_LOG_FILE,8,"CompareClusterConf Server Matches in Both Lists %s",tmpptrI->IpAddress);
				TAILQ_REMOVE(&RemoteList, tmpptrI, entries);
				free(tmpptrI);
				TAILQ_REMOVE(&LocalList, tmpptrJ, entries);
				free(tmpptrJ);
			}
		}
	}
*/
	for(tmpptrI = TAILQ_FIRST(&RemoteList), tmpptrJ = TAILQ_FIRST(&LocalList); (tmpptrI != NULL && tmpptrJ != NULL); 
			tmpptrI = tmpptrvalI, tmpptrJ = tmpptrvalJ)
	{

		tmpptrvalI = TAILQ_NEXT(tmpptrI, entries);
		tmpptrvalJ = TAILQ_NEXT(tmpptrJ, entries);

		if(!strcmp(tmpptrI->IpAddress, tmpptrJ->IpAddress))
		{
			TAILQ_REMOVE(&RemoteList, tmpptrI, entries);
			if(tmpptrI)
			{
				free(tmpptrI);
			}
			
			TAILQ_REMOVE(&LocalList, tmpptrJ, entries);
			
			if(tmpptrJ)
			{
				free(tmpptrJ);
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"CompareClusterConf: Mismatch in cluster conf, resetting conf.");
			break;
		}
	}

	if(!TAILQ_EMPTY(&RemoteList))
	{
		*updateConfigFile = 1;
		struct serversList* tmpptr;
		TAILQ_FOREACH(tmpptr,&RemoteList,entries)
		{
			TAILQ_REMOVE(&RemoteList,tmpptr,entries);
			//debug_print(INFOAGENT_LOG_FILE,8,"CompareClusterConf Remaining Entries in Remote %s",tmpptr->IpAddress);
			if(tmpptr)
			{
				free(tmpptr);
			}
		}
	}

	if(!TAILQ_EMPTY(&LocalList))
	{
		*updateConfigFile = 1;
		struct serversList* tmpptr;
		TAILQ_FOREACH(tmpptr,&LocalList,entries)
		{
			TAILQ_REMOVE(&LocalList,tmpptr,entries);
			//debug_print(INFOAGENT_LOG_FILE,8,"CompareClusterConf Remaining Entries in Local %s",tmpptr->IpAddress);
			if(tmpptr)
			{
				free(tmpptr);
			}
		}
	}

	return true;
}

void FreeRemoteListMemory()
{
	//struct serversList* tmpptr = NULL;
	/* Delete. */
	int delEntryCount = 0;
	//debug_print(INFOAGENT_LOG_FILE,8,"Deleting Remaining Entries in Remote");
	while(RemoteList.tqh_first != NULL)
	{
		delEntryCount++;
		TAILQ_REMOVE(&RemoteList, RemoteList.tqh_first, entries);
	}
	//debug_print(INFOAGENT_LOG_FILE,8,"Total Number of deleted Entries %d",delEntryCount);
	/*if(!TAILQ_EMPTY(&RemoteList))
	  {
	  struct serversList* tmpptr;
	  TAILQ_FOREACH(tmpptr,&RemoteList,entries)
	  {
	  TAILQ_REMOVE(&RemoteList,tmpptr,entries);
	  debug_print(INFOAGENT_LOG_FILE,8,"CompareClusterConf Remaining Entries in Remote %s\n",tmpptr->IpAddress);
	  free(tmpptr);
	  }

	  }*/
}

bool UpdateFileSynConf(CONFIG_DATA *clusterConf, int nodeType, int *isModified)
{
	char *tmptok = NULL;
	struct stat st;
	char* serverListptr = NULL;
	bool ifCheckUpdate = false;	

	struct serversList* tmpptr1 = NULL;
	struct serversList* tmpptr2 = NULL;

	char realServersList[MAX_NUMBER_OF_REAL_SERVERS*40] = {0};

	serverListptr = (char*)malloc(sizeof(clusterConf->RealServer));

	/*isModified is NULL When Node Is ACTIVE Load Balancer OR Writing FileSync Conf File For First Time in any Case..*/	
	ifCheckUpdate = false;
	if(nodeType != ACTIVE_LOAD_BALANCER)
	{
		if(isModified != NULL)
			ifCheckUpdate = true;
	}

	if(ifCheckUpdate)
	{
		tmpptr1 = (struct serversList*)malloc(sizeof(struct serversList));
		tmpptr2 = (struct serversList*)malloc(sizeof(struct serversList));

		if(!tmpptr1 || !tmpptr2)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"memory allocation failed.");
		}
	}

	if(serverListptr != NULL)
	{
		memset(serverListptr,0,sizeof(clusterConf->RealServer));
		sprintf(serverListptr,"%s",clusterConf->RealServer);
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"malloc call failed.");
		return false;
	}	

	if(ifCheckUpdate)
	{
		TAILQ_INIT(&RemoteList);
		TAILQ_INIT(&LocalList);

		if((tmpptr1 != NULL) && (tmpptr2 != NULL))
		{
			strcpy(tmpptr1->IpAddress,clusterConf->ActivePrivateIP);
			strcpy(tmpptr2->IpAddress,clusterConf->BackupPrivateIP);
			tmpptr1->IpAddress[strlen(tmpptr1->IpAddress)] = '\0';
			tmpptr2->IpAddress[strlen(tmpptr2->IpAddress)] = '\0';
			TAILQ_INSERT_TAIL(&RemoteList,tmpptr1,entries);
			TAILQ_INSERT_TAIL(&RemoteList,tmpptr2,entries);
		}
	}
	
	sprintf(realServersList,"SERVERS=%s,%s",clusterConf->ActivePrivateIP,clusterConf->BackupPrivateIP);	

	debug_print(INFOAGENT_LOG_FILE,8,"cluster conf read as server: active ipadd [%s], backup ipadd [%s]", clusterConf->ActivePrivateIP,clusterConf->BackupPrivateIP);
	tmptok = strtok(serverListptr,",");

	do{
		if((strcmp(tmptok,clusterConf->ActivePrivateIP)!= 0) && 
				(strcmp(tmptok,clusterConf->BackupPrivateIP) != 0))
		{
			if(ifCheckUpdate)
			{
				struct serversList* tmpptr = (struct serversList*)malloc(sizeof( struct serversList));
				/*Fill Remote List for comparision.*/
				if(tmpptr)
				{
					memset(tmpptr,0,sizeof(struct serversList));
					sprintf(tmpptr->IpAddress,"%s",tmptok);

					if(tmpptr->IpAddress[strlen(tmpptr->IpAddress)-1] == '\n')
						tmpptr->IpAddress[strlen(tmpptr->IpAddress)-1] = '\0';
					if(tmpptr->IpAddress[strlen(tmpptr->IpAddress)] == 0)
						tmpptr->IpAddress[strlen(tmpptr->IpAddress)] = '\0';

					//ADD_INTO_REMOTE_LIST_OF_CONFIGURATION(tmpptr);
					//debug_print(INFOAGENT_LOG_FILE,8,"added entry to remote list as %s", tmpptr->IpAddress);
					TAILQ_INSERT_TAIL(&RemoteList, tmpptr, entries);
				}
			}	
			
			strcat(realServersList,",");
			strcat(realServersList,tmptok);
		}
		
		tmptok = strtok(NULL,",");	
	}while(tmptok != NULL);

	if(!ifCheckUpdate && (stat(FILESYNC_CONFIGURATION_FILE,&st)!= 0))
	{
		//debug_print(INFOAGENT_LOG_FILE,8,"Writing FileSync Configuration File.");
		WriteSynConfFile(realServersList);

		//FreeRemoteListMemory();
	}
	else
	{
		if(isModified)
			*isModified = 0;
		if(!FillLocalClusterConf())
		{
			if(stat(FILESYNC_CONFIGURATION_FILE,&st)!= 0)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Filling Local Cluster Information Failed. File Doesn't Exist");
				return false;
			}
			debug_print(INFOAGENT_LOG_FILE,8,"Filling Local Cluster Information From Conf File Failed.");
			return false;
		}	
		/*Test If Any Changes Happened in Cluster Configuration*/
		int updateConfigFile = -1;	
		if(!CompareClusterConf(&updateConfigFile))
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Comparsion Failed. Failed To compare Local Conf To Remote Conf.");
			return false;
		}
		else if(updateConfigFile == 1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Comparsion Found Some Changes In Cluster Configuration");
			if(isModified)
				*isModified = 1;
			WriteSynConfFile(realServersList);
		}
		else
			debug_print(INFOAGENT_LOG_FILE,8,"Comparsion Found No Changes In Cluster Configuration");

	}	
	
	if(serverListptr != NULL)
		free(serverListptr);

	return true;
}

#define MAX_INTERFACES					5
static char MyInterfaceip[56] = {0};

char *GetInterfaceInfo(char* interfaceName)
{
	int sockfd;
	struct ifreq ifr;

	//debug_print(INFOAGENT_LOG_FILE,8,"Getting ip address against interface %s",interfaceName);
        memset(MyInterfaceip,'0',sizeof(MyInterfaceip));

	sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if(sockfd != -1)
	{
		ifr.ifr_addr.sa_family = AF_INET;
		strcpy(ifr.ifr_name,interfaceName);

		if(ioctl(sockfd, SIOCGIFADDR, &ifr) == -1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"ioctl failed error %s",strerror(errno));
                        memset(MyInterfaceip,'0',sizeof(MyInterfaceip));
                        close(sockfd);
                        return MyInterfaceip;
		}

		close(sockfd);
		//debug_print(INFOAGENT_LOG_FILE,8,"GetInterfaceInfo returned, interface [%s], ipaddress [%s]",interfaceName,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
		strcpy(MyInterfaceip,inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
	}
	else
                debug_print(INFOAGENT_LOG_FILE,8,"socket call failed, reason %s",strerror(errno));

        return MyInterfaceip;
}

#if 0
char* GetInterfaceInfo(char* interfaceName)//, struct in_addr* retaddr)
{
	int sockfd;
	struct ifreq ifr[MAX_INTERFACES],*pIfr = NULL;
	struct ifconf ifc;

	debug_print(INFOAGENT_LOG_FILE,8,"Getting ip address against interface %s",interfaceName);
	memset(MyInterfaceip,'0',sizeof(MyInterfaceip));
	sockfd = socket(AF_INET, SOCK_STREAM,0);
	if(sockfd != -1)
	{
		ifc.ifc_req = NULL;
		ifc.ifc_req = ifr;

		ifc.ifc_len = sizeof(ifr);
	
		errno = 0;
		if(ioctl(sockfd, SIOCGIFCONF, &ifc) == -1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"ioctl failed error %s",strerror(errno));
			memset(MyInterfaceip,'0',sizeof(MyInterfaceip));
			close(sockfd);
			return MyInterfaceip;
		}

		pIfr = ifc.ifc_req;
		debug_print(INFOAGENT_LOG_FILE,8,"Number of interfaces returned from ioctl %d",(ifc.ifc_len)/sizeof(struct ifreq));
		for(; (char *)pIfr < (char *)ifc.ifc_req + ifc.ifc_len; ++pIfr)
		{
			if(!strcmp(pIfr->ifr_name,interfaceName))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Interface name matched, getting ip address intf[%s]:ip[%s]",
						pIfr->ifr_name,inet_ntoa(((struct sockaddr_in *)pIfr->ifr_addr)->sin_addr));	
				close(sockfd);
				strcpy(MyInterfaceip,inet_ntoa(((struct sockaddr_in *)pIfr->ifr_addr)->sin_addr));
				return MyInterfaceip;
			}
			
			if(pIfr->ifr_addr.sa_data == (pIfr + 1)->ifr_addr.sa_data)
			{
				continue;
			}
			
			if(ioctl(sockfd, SIOCGIFFLAGS, pIfr))
			{
				continue;
			}
		}
		
		close(sockfd);
	}
	else
		debug_print(INFOAGENT_LOG_FILE,8,"socket call failed, reason %s",strerror(errno));

	debug_print(INFOAGENT_LOG_FILE,8,"Failed to get ip against interface %s",interfaceName);
	return MyInterfaceip;
}
#endif

int setSockreuse(int sockfd)
{
	int on = 1;
	if(setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR , (char*)&on, sizeof(on)) == -1) 
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Set Socket Option Failed to set reuse addr.");
		return -1;
	}
	else
		return 0;
}

bool SendStatusOfAllNodesToCGI(int clientSock)
{
	char* bufferWrite = NULL;

	if(g_NumNodes > 0)
	{	
		bufferWrite = (char *)malloc(sizeof(CONFCOMMAND)+(sizeof(STATUSNODE)*g_NumNodes));
		memset(bufferWrite,'\0', sizeof(CONFCOMMAND)+(sizeof(STATUSNODE)*g_NumNodes));
		if(bufferWrite)
		{
			CONFCOMMAND* respCommand = (CONFCOMMAND* )bufferWrite;
			STATUSNODE* respNodesStatus = (STATUSNODE* )(bufferWrite + sizeof(CONFCOMMAND));

			respCommand->service = STATUS_RESPONSE_REQ_CGI;//0x81;
			respCommand->command = g_NumNodes;

			debug_print(INFOAGENT_LOG_FILE,8,"Sending Status Data of total [%d] nodes to CGI.",g_NumNodes);

			pthread_mutex_lock(&g_NodesStatPtr_mutex);
			memcpy(respNodesStatus,g_NodesStatPtr,(sizeof(STATUSNODE)*g_NumNodes));
			pthread_mutex_unlock(&g_NodesStatPtr_mutex);

			if(!SendData(clientSock,(char *)respCommand,sizeof(CONFCOMMAND)+(sizeof(STATUSNODE)*g_NumNodes)))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: SendStatusOfAllNodesToCGI failed.");
			}

			if(bufferWrite)
			{		
				free(bufferWrite);
				bufferWrite = NULL;
			}
		}
		else
		{
			CONFCOMMAND respCommand;
                        respCommand.service = STATUS_RESPONSE_REQ_CGI;
                        respCommand.command = 0;

                        if(!SendData(clientSock,(char *)&respCommand,sizeof(CONFCOMMAND)))
                        {
                                debug_print(INFOAGENT_LOG_FILE,8,"Active LB: SendStatusOfAllNodesToCGI failed to send status of zero nodes.");
                        }
		}
	}
	else
	{
			CONFCOMMAND respCommand;
			respCommand.service = STATUS_RESPONSE_REQ_CGI;
			respCommand.command = 0;
			
			if(!SendData(clientSock,(char *)&respCommand,sizeof(CONFCOMMAND)))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: SendStatusOfAllNodesToCGI failed to send status of zero nodes.");
			}
	}

	return true;
}

void HandleRequestFromOtherActiveNode(int clientSock)
{
	debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Other Gateway is also running Active Server");
	if(backupActive)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Active LB: YES I am the backup active Node. Means a node running active HA when actual primary is down.");
		if(wait_ticks == 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Active LB: I am a backup node running active. Lets Go to Backup Mode.");
			PutRestartRequestInHALogs("Active InfoAgent sending command for Pulse restart in event of other node also running active and I am configured as backup.");	
			if(!SendCommandToDaemon(PULSE_RESTART))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Failed to send Pulse Restart command to daemon");
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"Sent command for Pulse restart, Now i am exiting.");
				exit(EXIT_SUCCESS);
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"I am BackupActive, Just decrementing count by one. Will Change my role in next such request pkt.");
			wait_ticks = wait_ticks - 1;
			// Send Other node also to restart its Pulse.
			CONFCOMMAND rebootPulse;
                        rebootPulse.service = RESTART_YOUR_PULSE_IF_BACKUP;
                        rebootPulse.command = 0x1;
                        rebootPulse.relay = 0x1;
                        if(!SendData(clientSock,(char *)&rebootPulse,sizeof(CONFCOMMAND)))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: SendData failed for RESTART_YOUR_PULSE_IF_BACKUP.");
			}
		}	
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Active LB: I am not backup active node.");
	}	
}

void *startCommandServer(void* arg)
{
	struct sockaddr_in clientSockAddr;
	socklen_t sockLen = sizeof(struct sockaddr_in);
	
	signal(SIGTERM,HandleSigTerm);
	if(!StartListner())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Starting Active Load Balancer Listner Failed.");
		return NULL;
	}

	CONFCOMMAND buffer;
	int clientSock = -1;	
	int data_len;

	while(!g_CondVar)
	{
		clientSock = accept(ListenAgentSock,(struct sockaddr*)&clientSockAddr,&sockLen);
		if(clientSock < 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"ActiveListner: Accept Failed. Thread Exiting.");
			if(errno == EINTR)
			{
				if(g_CondVar == 1)
                                        return NULL;
				else
					continue;
			}
			else
				return NULL;	
		}
		else
			debug_print(INFOAGENT_LOG_FILE,8,"ActiveListner: Got request from %s",inet_ntoa(clientSockAddr.sin_addr));	
		//ValidateClientIP() // DROP IP address which are not from known real servers.
		memset(&buffer,'\0',sizeof(CONFCOMMAND));

		RecvData(clientSock,(char*)&buffer,sizeof(CONFCOMMAND),&data_len);
		if(data_len <= 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"ActiveListner: Read Data Failed/Close.");
			close(clientSock);
			continue;
		}
		
		if(data_len == sizeof(CONFCOMMAND))
		{
			//debug_print(INFOAGENT_LOG_FILE,8,"Active LoadBalancer Recieved Command %x Service %x",buffer.command,buffer.service);

			if(buffer.service == STATUS_RESPONSE_REQ_CGI)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LoadBalancer Recieved request from CGI, sending status.");
				SendStatusOfAllNodesToCGI(clientSock);
			}
			else if(buffer.service == ACTIVE_LOAD_BALANCER)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LoadBalancer Recieved request from Other Active Node in cluster.");
				HandleRequestFromOtherActiveNode(clientSock);		
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Got Unknown request type.");
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Expecting request from CGI/Other Active Node. Service Type read as %d",buffer.service);
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Here My Node Type is ");
			}

			close(clientSock);
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Command read from other node doesn't sent enough bytes. sent [%d], expected [%d]",data_len,sizeof(CONFCOMMAND));
			close(clientSock);
		}
	}

	debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Active Node Listener Exiting.");
	close(ListenAgentSock);
	pthread_exit(NULL);
}

void  makeBackupFescommon(void * arg)
{
	while(!g_CondVar)
	{
		system("touch /home/fes/fescommon/*");
		system("touch /var/lib/mysql/fesdb/*");
		system("touch /var/lib/mysql/mysql/*");
		system("touch /etc/sysconfig/ha/lvs.cf");
		sleep(180);
	}
}

bool to_float(const char *s, float *dest) 
{
	if(s == NULL) 
	{
		return false;
	}
	
	char *endptr;
	*dest = (float) strtod(s, &endptr);
	if(s == endptr) 
	{
		return false; // no conversion;
	}
	
	// Look at trailing text
	while(isspace((unsigned char ) *endptr))
		endptr++;
	return *endptr == '\0';
}
          
bool is_valid_int(char *s)
{
	long long temp = 0;
	bool negative = false;
	if (*s != '\0' && (*s == '-' || *s == '+')) {
		negative = *s++ == '-';
	}

	while (*s != '\0') {
		if (!isdigit((unsigned char)*s)) {
			if(*s == '\n')
                        {
                                *s = '\0';
                                return true;
                        }
			return false;
		}
		temp = 10 * temp + (*s - '0');
		if ((!negative && temp > INT_MAX) || (negative && -temp < INT_MIN)) {
			return false;
		}
		++s;
	}

	return true;
}
 
int getNodeStatusDetail(STATUSNODE* node, int nodeType, char* IPaddrs)
{
	char result[32] = {0};
	char bigResult[512] = {0};
	int retstat = -1;
	STATUSNODE* selfStat = node;
	int founddigit = false;

	char upt_cmd[] = "uptime| awk -F , 'BEGIN{search=\" \";timesval=0;} {k=split($0,array1,\",\"); n=split($1,array,search); if(k < 6){ if(n<4){printf(\"%s hrs \",array[3])}else{printf(\"%s %s \",array[3],array[4]);}}else {j=split($2,array3,\" \"); if(j >1){printf(\"%s days,%s mins\",array[3],array3[1]);}else{ printf(\"%s days,%s hrs\",array[3],$2);}} }'";

	char cpu_cmd[] = "/usr/bin/sar -u 1 1 | grep Average | grep -v grep | awk '{print $8}'";
	char hdd_cmd[] = "/usr/bin/df | if (/bin/mount | /bin/grep 'type ext3' | /bin/grep ' /home ' > /dev/null 2>&1); then (/bin/grep `/bin/mount | /bin/grep \"type ext3\" | /bin/grep \" /home \" | /bin/awk '{print $1}'`); else (/bin/grep `/bin/mount | /bin/grep \"type ext3\" | /bin/grep \" / \" | /bin/awk '{print $1}'`); fi | /bin/awk '{print $5}'";
	//char hdd_cmd[] = "/usr/bin/df | grep `mount | grep \"type ext3\" | grep \" /home \" | awk '{print $1}'` | awk '{print $5}'";
	// for aws
	//char hdd_cmd[] = "/usr/bin/df | grep `mount | grep \"type xfs\" | grep \" / \" | awk '{print $1}'` | awk '{print $5}'"; 
	char mem_cmd[] = "/usr/bin/free | awk 'BEGIN {MODIFY_Conuter=0} {if(MODIFY_Conuter == 2){y=($3/($3+$4))*100; print y; MODIFY_Conuter++;} else {MODIFY_Conuter++;}}'";
	// for aws
	//char mem_cmd[] = "/usr/bin/free | awk 'BEGIN {MODIFY_Conuter=0} {if(MODIFY_Conuter == 1){y=($7/($2))*100; print y; MODIFY_Conuter++;} else {MODIFY_Conuter++;}}'";

	memset(selfStat,'\0',sizeof(STATUSNODE));
	selfStat->status_bit = 0;
	memcpy(selfStat->nodeIP, IPaddrs, sizeof(selfStat->nodeIP));
	selfStat->NodeType = nodeType;

	//debug_print(INFOAGENT_LOG_FILE,8,"Writing data as node type [%d].",selfStat->NodeType);

	if(nodeType != REAL_VPN_SERVER)
	{
		memset(result,0,sizeof(result));
		if(!getcmdvals("service pulse status > /dev/null 2>&1; echo $?",result,sizeof(result)))
		{
			if(is_valid_int(result))
			{
				retstat = atoi(result);
				if(!retstat)
				{		
					//debug_print(INFOAGENT_LOG_FILE,8,"Pulse service Running.");
					selfStat->status_bit = selfStat->status_bit | PULSE_RUNNING;
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Pulse Not Running.");

				}
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Pulse Status fetch command failed.");
		}
	}

	memset(result,0,sizeof(result));
	if(!getcmdvals("pgrep FileSync > /dev/null 2>&1; echo $?",result,sizeof(result)))
	{
		if(is_valid_int(result))
		{
			retstat = atoi(result);
			if(!retstat)
			{	
				//debug_print(INFOAGENT_LOG_FILE,8,"FileSync service Running.");
				selfStat->status_bit = selfStat->status_bit | FILESYNC_DAEMON_RUNNING;
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: FileSync Daemon Not Running");
			}
		}	
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: FileSync Status fetch command failed.");
	}

	memset(result,0,sizeof(result));
	if(!getcmdvals("pgrep fesgeneric > /dev/null 2>&1; echo $?",result, sizeof(result)))
	{
		if(is_valid_int(result))
		{
			retstat = atoi(result);
			if(!retstat)
			{
				memset(result,0,sizeof(result));
				if(!getcmdvals("pgrep progeneric > /dev/null 2>&1; echo $?",result, sizeof(result)))
				{
					if(is_valid_int(result))
					{
						retstat = atoi(result);
						if(!retstat)
						{
							selfStat->status_bit = selfStat->status_bit | VPN_SERVER_RUNNING; 
						}
						else
						{
							debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: VPN services not running");
						}
					}
				}
				else
					debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: VPN Server Status fetch command failed.");
			}
			else
				debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Fesgeneric is down");
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: VPN Server Status fetch command failed.");
	}

	memset(bigResult,'\0',sizeof(bigResult));
	if(!getcmdvals(upt_cmd, bigResult, sizeof(bigResult) - 1))
	{
		if(strlen(bigResult) <= sizeof(selfStat->sysUpTime))
		{
			if(strstr(bigResult,"min") || strstr(bigResult,"hrs") || strstr(bigResult,"days"))
			{
				bigResult[sizeof(selfStat->sysUpTime) - 1] = '\0';
				sprintf(selfStat->sysUpTime, "%s", bigResult);
			}	
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Failed to get uptime, read output %s",bigResult);
                        	strncpy(selfStat->sysUpTime, "NA", sizeof(selfStat->sysUpTime) - 1);
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Failed to get uptime, read output %s",bigResult);
			strncpy(selfStat->sysUpTime, "NA", sizeof(selfStat->sysUpTime) - 1);
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Failed to read uptime status.");
		strncpy(selfStat->sysUpTime, "NA", sizeof(selfStat->sysUpTime) - 1);
	}

	memset(bigResult,'\0',sizeof(bigResult));
	if(!getcmdvals(cpu_cmd, bigResult, sizeof(bigResult) - 1))
	{
		if(strlen(bigResult))
		{
			int i = 0;
                        while(i < strlen(bigResult))
                        {
                                if((bigResult[i] >= '0' && bigResult[i] <= '9') || (bigResult[i] == '.') || (bigResult[i] == '\n'))
                                {
                                        founddigit = true;
                                        if((bigResult[i] == '\n'))
                                        {
                                                bigResult[i] = '\0';
                                                break;
                                        }
                                }
                                else
                                {
					debug_print(INFOAGENT_LOG_FILE,8,"check for digit failed while cpu calc. char was %c",bigResult[i]);
                                        founddigit = false;
                                        break;
                                }

                                i++;
                        }

			if(founddigit)
			{
				float temp;
				if(to_float(bigResult,&temp))
				{
					float idlet = atof(bigResult);
					float percentage = 100.0;
					percentage = percentage - idlet;
					sprintf(selfStat->cpu,"%f",percentage);
					selfStat->cpu[strlen(bigResult)] = '\0';
				}
			}
			else
				sprintf(selfStat->cpu,"%s","NA");
		}
		else
			sprintf(selfStat->cpu,"%s","00");
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: failed to read CPU status.");	
		sprintf(selfStat->cpu,"%s","00");
	}

	founddigit = false;
	memset(bigResult,'\0',sizeof(bigResult));
	if(!getcmdvals(hdd_cmd,bigResult,sizeof(bigResult) - 1))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"hdd output read as %s",bigResult);
		if(strlen(bigResult))
		{	
			int i = 0;
			while(i < strlen(bigResult))
			{
				if((bigResult[i] >= '0' && bigResult[i] <= '9') || (bigResult[i] == '%') || (bigResult[i] == '\n'))
				{
					founddigit = true;
					if((bigResult[i] == '%') || (bigResult[i] == '\n'))
					{
						bigResult[i] = '\0';
						break;
					}
				}
				else
                        	{
					debug_print(INFOAGENT_LOG_FILE,8,"check for digit failed while hdd calc. char was %c",bigResult[i]);
                                	founddigit = false;
                                	break;
                        	}
				
				i++;
			}

			if(founddigit)
				sprintf(selfStat->secMem, "%s", bigResult);
			else
				sprintf(selfStat->secMem, "%s", "NA");
		}
		else
			sprintf(selfStat->secMem,"%s","00");
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Failed To Read Disk Status.");
		sprintf(selfStat->secMem, "%s", "00");
	}

	founddigit = false;
	memset(bigResult,'\0',sizeof(bigResult));
	if(!getcmdvals(mem_cmd, bigResult, sizeof(bigResult) - 1))
	{		
		int i = 0;
		while(i < strlen(bigResult))
		{
			if((bigResult[i] >= '0' && bigResult[i] <= '9') || (bigResult[i] == '.') || (bigResult[i] == '\n'))
			{
				founddigit = true;
				if(bigResult[i] == '\n')
				{
					bigResult[i] = '\0';
					break;
				}
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"check for digit failed while mem. char was %c",bigResult[i]);
				founddigit = false;
				break;
			}
			
			i++;
		}

		if(founddigit)
			sprintf(selfStat->mem, "%s", bigResult);
		else
			sprintf(selfStat->mem, "%s", "NA");
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"GetNodeStatus: Failed To Read Mem Status.");
		sprintf(selfStat->mem,"%s","00");
	}
	
	return 0;
}

int sendStatusPackage(int socketfd,int nodeType,char* IPaddrs)
{
	int len = 0;
	char statBuff[(sizeof(CONFCOMMAND)+sizeof(STATUSNODE))] = {0};
	CONFCOMMAND respCommand;
	STATUSNODE selfStat;
	//static int backupwait_ticks = 1;	

	getNodeStatusDetail(&selfStat,nodeType,IPaddrs);

#if 0
	if(IFIamPrimaryNodeRunningInactive())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: as i am primary, telling other node to restart his pulse, so that it becomes inactive automatically.");
		if(backupwait_ticks <= 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Telling other node to restart its pulse.");
			respCommand.service = RESTART_YOUR_PULSE_IF_BACKUP;
		}
		else
			respCommand.service = PASSIVE_INFO_SENDING_NODE_STATUS;
		
		backupwait_ticks--;
		if(backupwait_ticks < -1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Why other node is still not restarting its pulse.");
		}
	}
	else
#endif
		respCommand.service = PASSIVE_INFO_SENDING_NODE_STATUS; //0x81;
	
	respCommand.command = 0x09;

	memcpy(statBuff,&respCommand,(sizeof(CONFCOMMAND)));
	memcpy(statBuff+(sizeof(CONFCOMMAND)),&selfStat,(sizeof(STATUSNODE)));

	len = (sizeof(CONFCOMMAND)+sizeof(STATUSNODE));
	if(!SendData(socketfd,statBuff,len))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: SendData failed for sendStatusPackage.");		
		return 0;
	}
	//else
	//	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: successfully wrote %d bytes of status pkt to active node",len);
		
	return 1;
}

bool StartListner()
{
	struct sockaddr_in sockAddr;
	int sockLen = -1;

	ListenAgentSock = socket(PF_INET,SOCK_STREAM,0);
	if(ListenAgentSock < 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Startup server failed To Intialize Socket.");
		return false;
	}

	setSockreuse(ListenAgentSock);
	sockAddr.sin_family = AF_INET;
	sockAddr.sin_port = htons(INFOAGENT_SERVICE_PORT);
	sockAddr.sin_addr.s_addr = htonl(INADDR_ANY);
	sockLen = sizeof(sockAddr);
	
	int ONE = 1;
	socklen_t len = sizeof(ONE);
	if(setsockopt(ListenAgentSock,SOL_SOCKET,SO_REUSEADDR,&ONE,len) == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: setsockopt failed to set reuse addr. Error is %s",strerror(errno));
		return false;	
	}

	errno = 0;
	if(bind(ListenAgentSock,(struct sockaddr *)&sockAddr,sockLen) == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Startup server failed To bind Socket. Bind Error %s",strerror(errno));
		// Put here code to restart other instance
		return false;
	}

	errno = 0;	
	if(listen(ListenAgentSock,MAX_LISTEN_BACKLOG_LIMIT) == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To start Listner Socket. Listen Error %s",strerror(errno));
		return false;
	}
	
	return true;
}

#define MAX_TIMEDIFF_PASSIVE_AND_ACTIVE				60

bool SyncMyTimeWithActive(char *activeserverzone, time_t activeMachineTime)
{
	char zonename[256] = {0};
	
	memset(zonename,0,sizeof(zonename));
	getTimeZoneDetails(zonename);
	if(strcmp(activeserverzone,zonename))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: My time Zone is different than Active Server, Exiting");
		return false;
	}
	else 
	{
		time_t now = time(NULL);
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Time Difference Mine[%d] - Active[%d] = %d secs",(unsigned int)now,(unsigned int)activeMachineTime,(unsigned int)(now - activeMachineTime));
		if(abs(now-activeMachineTime) > MAX_TIMEDIFF_PASSIVE_AND_ACTIVE)//|| (now > (activeMachineTime+2)))
		{	
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: WARNING Running with a time difference more than ONE minute!!!");	
			/*SYNC TIME WITH ACTIVE SERVER.*/
			char cmd[512] = {0};
			sprintf(cmd,"echo \"date -s \\\"$(date -d @%d)\\\"\" > /tmp/timeset.sh",(int)activeMachineTime+1);
			system(cmd);
			system("echo \"hwclock --systohc\" >> /tmp/timeset.sh");
			system("chmod ugo+x /tmp/timeset.sh > /dev/null 2>&1");
			PutRestartRequestInHALogs("Passive InfoAgent sending command for time sync.");	
			if(!SendCommandToDaemon(SYNC_TIME))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo:: Failed To Sync Time Between Servers.");
				return false;
			}
			
			/*if(now > activeMachineTime)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: My time is higher than active server.");
			}
			else
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Active server time is higher than Me.");

			sprintf(cmd,"/usr/bin/date -s \"$(/usr/bin/date -d @%d)\"",(int)activeMachineTime);
			system(cmd);
			system("/usr/sbin/hwclock --systohc > /dev/null 2>&1");	*/
		}
		else	
			debug_print(INFOAGENT_LOG_FILE,8,"TimeDiff between active and Me is lesser than %d secs. It is OK!",
				MAX_TIMEDIFF_PASSIVE_AND_ACTIVE);
	}

	return true;
}

#if 0
bool AddIptableCommands(char *VirtualIP, char *selfintface, char *selfIPaddress, )
{
		
}
#endif

bool AddIptableCommandsToAcceptsVIPPkts(char *VirtualIP,char *selfintface,char *selfIPaddress)
{
	char IptableCommand[512] = {0};
	
	debug_print(INFOAGENT_LOG_FILE,8,"Calling IP Tables PreRouting Commands To Accept traffic with IP as VIP.");

	system("iptables -t nat -F");

	sprintf(IptableCommand,"iptables -t nat -A PREROUTING -i %s -d %s -p tcp --dport %d -j DNAT --to %s ",selfintface,VirtualIP,80,selfIPaddress);
	system(IptableCommand);

	sprintf(IptableCommand,"iptables -t nat -A PREROUTING -i %s -d %s -p tcp --dport %d -j DNAT --to %s ",selfintface,VirtualIP,443,selfIPaddress);
	system(IptableCommand);

	return true;
}

int DetermineSelfNodeType(CONFIG_DATA* confbuffer, char* selfIP)
{
	int type = 0;
	char serverlist[MAX_NUMBER_OF_REAL_SERVERS*40] = {0};

	if(strcmp(confbuffer->BackupPrivateIP,selfIP) == 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: I am a Load balancer + VPN server.");
		type = STANDBY_LOAD_BALANCER;
	}

	sprintf(serverlist,"%s",confbuffer->RealServer);

	char* tempserver = strtok(serverlist,",");
	do{
		/*If My IP Address also in real server List I am LOAD_BALANCER_WITH_VPN_SERVER.*/
		if(strcmp(tempserver,selfIP) == 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: I am a real VPN server only.");
			type |= REAL_VPN_SERVER;
		}

		tempserver = strtok(NULL,",");

	}while(tempserver != NULL);

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Getting active/inactive by comparing ip %s on interface %s to %s",confbuffer->primaryIP,confbuffer->IntfName,selfIP);
	if(!strcmp(confbuffer->primaryIP,selfIP))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: I am inactive running. I am configured as primary node. Why I am doing this.");
		primaryActive = false;
		primaryInActive	= true;
		backupActive = true;
		backupInActive = false;
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Let us first check what other node is running then decide."); 
	}
	else if(!strcmp(confbuffer->backupIP,selfIP))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: I am inactive running. I am configured as backup node. its OK");
		primaryActive = true;
                primaryInActive = false;
                backupActive = false;
                backupInActive = true;
	}
	
	return type;
}

bool HandleOneTimeActivityPassiveServer(int clientSock, char *selfIP, CONFIG_DATA *confbuffer, char *ActiveLBIP, char *VirtualIP, int *selfType, char *readData)
{
	/*This is ONLY One Time and First Iteration Of StandBy Server and Real Server.*/
	time_t activeMachineTime = -1;

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: First Iteration Setting Variables.");
	
	REALSERVER SelfSharedInfo;
	
	memset(&SelfSharedInfo,'\0',sizeof(REALSERVER));
	
	confbuffer = (CONFIG_DATA*)(readData + sizeof(CONFCOMMAND));  
	if(confbuffer)
	{
		sprintf(selfIP,"%s",GetInterfaceInfo(confbuffer->IntfName));//inet_ntoa(GetInterfaceInfo(confbuffer->IntfName)));
		sprintf(SelfSharedInfo.IPaddress,"%s",selfIP);
		sprintf(SelfSharedInfo.IntfName,"%s",confbuffer->IntfName);
		sprintf(SelfSharedInfo.ActiveIPAddress,"%s",confbuffer->ActivePrivateIP);
		sprintf(SelfSharedInfo.BackupIPAddress,"%s",confbuffer->BackupPrivateIP);
		sprintf(SelfSharedInfo.VirtualIPAddress,"%s",confbuffer->ClusterVirtualIP);
		sprintf(SelfSharedInfo.RealServer,"%s",confbuffer->RealServer);
		SelfSharedInfo.num_realservers = confbuffer->num_realservers; 
		activeMachineTime = strtol(confbuffer->current_time,NULL,10);

		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Setting Cluster conf self-ip %s ,intface %s, ActiveIP %s VirtIP %s TimeZone %s Realservercount %d",selfIP,confbuffer->IntfName,confbuffer->ActivePrivateIP,confbuffer->ClusterVirtualIP,confbuffer->zonename,confbuffer->num_realservers);
	}
	
	if(!SyncMyTimeWithActive(confbuffer->zonename,activeMachineTime))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"SyncMyTimeWithActive failed.");	
	}
	
	SelfSharedInfo.type = DetermineSelfNodeType(confbuffer,selfIP);
	if(SelfSharedInfo.type == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"DetermineSelfNodeType failed.");
	}
	
	*selfType = SelfSharedInfo.type;
	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Replying Active Server With Status packet.");
	sendStatusPackage(clientSock, SelfSharedInfo.type, selfIP);

	if(!FillNodeInfoIntoSharedMemory(&SelfSharedInfo))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Fill Information Into Shared Memory");
		return false;
	}

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: InfoAgent Updating FileSync Configuration File.");	
	if(!UpdateFileSynConf(confbuffer,*selfType,NULL))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Update FileSync Configuration File");
		return false;
	}

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: InfoAgent Launching FileSync Daemon In Start");
	if(!LaunchFileSyncDaemon())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Launch FileSync Daemon");
		return false;
	}

	memcpy(ActiveLBIP,confbuffer->ActivePrivateIP,strlen(confbuffer->ActivePrivateIP)); 

	if((strlen(VirtualIP) <= 0) || (strcmp(VirtualIP,confbuffer->ClusterVirtualIP) != 0))
	{
		memcpy(VirtualIP,confbuffer->ClusterVirtualIP,strlen(confbuffer->ClusterVirtualIP));
		if(SelfSharedInfo.type & REAL_VPN_SERVER)
		{
			AddIptableCommandsToAcceptsVIPPkts(VirtualIP,SelfSharedInfo.IntfName,SelfSharedInfo.IPaddress);
		}
	}

	if(!HandleHostedVirtualIPs())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: HandleHostedVirtualIPs failed.");
	}

	return true;	
}

bool IFIamPrimaryNodeRunningInactive()
{
	if(primaryInActive)
		return true;
	else
		return false;	
}

bool SyncTimeWithNTPServer(char* ntp)
{
	char cmd[1024] = {0};
	FILE* fp = NULL;
	char strfp[4] = {0};
	int st;

	sprintf(cmd,"/usr/sbin/ntpdate %s > /dev/null 2>&1; echo $?",ntp);

	debug_print(INFOAGENT_LOG_FILE,8,"ntp command fired is %s.",cmd);
	fp = popen(cmd,"r");
	if(fp != NULL)
	{
		fread(strfp,1,4,fp);
		debug_print(INFOAGENT_LOG_FILE,8,"Read bytes are %s.",strfp);
		if(strlen(strfp))
		{
			if(strfp[strlen(strfp) - 1] == '\n')
				strfp[strlen(strfp) - 1] = '\0';

			st = atoi(strfp);
			if(st)
			{
				pclose(fp);
				debug_print(INFOAGENT_LOG_FILE,8,"Sync with ntpserver [%s] failed.",ntp);
				return 0;
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Sync with ntpserver [%s] done.",ntp);
				pclose(fp);
				return 1;
			}
		}

		pclose(fp);
		return 0;
	}

	return 0;
}

bool SyncTimeToNTP()
{
	struct stat st;

	char ntp1[256] = {0};
        char ntp2[256] = {0};
        char intval[8] = {0};

        int issyncntp1alreadyattempted = 0;
        int issyncntp2alreadyattempted = 0;
	
	struct timeval now;
	static struct timeval ntpLastSyncTime = {0};

	gettimeofday(&now, NULL);
	if((ntpLastSyncTime.tv_sec + (ntpInterval*60)) < now.tv_sec)
	{
		if(!stat(NTP_SERVER_CONF_FILE, &st))
		{
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
								debug_print(INFOAGENT_LOG_FILE,8,"SYNC-ing with ntp %s", ntp1);
								if(SyncTimeWithNTPServer(ntp1))
								{
									ntpLastSyncTime.tv_sec = now.tv_sec;
									return true;
								}
								else if((issyncntp2alreadyattempted == 1))
								{
									ntpLastSyncTime.tv_sec = now.tv_sec;
									return false;
								}
								else
									issyncntp1alreadyattempted = 1;
							}
						}

						if(strstr(token,"NTP2="))
						{
							strcpy(ntp2,token + strlen("NTP2="));
							if(strlen(ntp2))
							{
								debug_print(INFOAGENT_LOG_FILE,8,"SYNC-ing with ntp %s", ntp2);
								if(SyncTimeWithNTPServer(ntp2))
								{
									ntpLastSyncTime.tv_sec = now.tv_sec;
									return true;
								}
								else if((issyncntp1alreadyattempted == 1))
								{
									ntpLastSyncTime.tv_sec = now.tv_sec;
									return false;
								}
								else
									issyncntp2alreadyattempted = 1;
							}
						}

						token = strtok(NULL,"\n");
					}
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"read failed for file %s, error %s",
						NTP_SERVER_CONF_FILE,strerror(errno)); 
					ntpInterval = DEFAULT_NTPINTERVAL;
					ntpLastSyncTime.tv_sec = now.tv_sec;
					return false;
				}
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"open failed for file %s, error %s",NTP_SERVER_CONF_FILE,strerror(errno)); 
				ntpInterval = DEFAULT_NTPINTERVAL;
				ntpLastSyncTime.tv_sec = now.tv_sec;
				return false;
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"stat failed for file %s, error %s",NTP_SERVER_CONF_FILE,strerror(errno)); 
			ntpInterval = DEFAULT_NTPINTERVAL;
			ntpLastSyncTime.tv_sec = now.tv_sec;
			return false;
		}
	}
	else
		debug_print(INFOAGENT_LOG_FILE,8,"NTP sync interval not yet expired.");
       
	//debug_print(INFOAGENT_LOG_FILE,8,"ntp sync returning failed or interval of %d secs not yet expired.",ntpInterval); 
	ntpLastSyncTime.tv_sec = now.tv_sec;
	return false;
}

#if 0
int ISVIPUp(char* device, char* vip)
{
		
}
#endif

void BringDownVirtualInterface(char* readData)
{
	char device[256] = {0};
	static int vipalreadyremoved = 0;

	if(vipalreadyremoved)
		return; 

	CONFIG_DATA* confbuffer = (CONFIG_DATA*)(readData + sizeof(CONFCOMMAND));
	if(confbuffer)
	{
		sprintf(device, "%s:1", confbuffer->IntfName);

		pid_t child;
		char* ifconfigArgs[5];
		int i = 0;

		ifconfigArgs[i++] = (char *) "/sbin/ifconfig";

		ifconfigArgs[i++] = device;
		ifconfigArgs[i++] = (char *) "down";
		ifconfigArgs[i++] = NULL;
		ifconfigArgs[4] = NULL;

		debug_print(INFOAGENT_LOG_FILE,8,"Passive: Removing %s interface!!", device);	
		if(!(child = fork()))
		{
			execv(ifconfigArgs[0], ifconfigArgs);
			exit(-1);
		}
		
		int attempt = 5;
		while(attempt)
		{
			int ret = 0;
			int status = 0;	
			ret = waitpid(child, &status, WNOHANG);
			if(ret == -1)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Passive: waitpid failed.");
				break;
			}
			else
			{

				if(ret != 0)
				{
					if(WIFEXITED(status))
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Passive: deleted the VIP on interface %s", device);
						debug_print(INFOAGENT_LOG_FILE,8,"Passive: exit status %d", WEXITSTATUS(status));
						if(WEXITSTATUS(status) != 0)
						{
							debug_print(INFOAGENT_LOG_FILE,8,								                                                                "Passive: failed to delete VIP. reason could be no existing VIP");
						}

						if(WEXITSTATUS(status) == 255)
							vipalreadyremoved = 1;
					}
					else
					{
						debug_print(INFOAGENT_LOG_FILE,8,
								"Passive: failed to delete VIP. child process exited unexpectedly.");
					}

					break;		
				}	
				
				sleep(1);
				attempt--;
			}
		}

		debug_print(INFOAGENT_LOG_FILE,8,"Passive: Removing vip function done !!");
	}
}

void StartPassiveServer()
{
	char VirtualIP[IPADRRESS_MAX_LEN] = {0};
	char ActiveLBIP[IPADRRESS_MAX_LEN] = {0};

	int selfType = -1;
	char selfIP[IPADRRESS_MAX_LEN] = {0};

	struct sockaddr_in clientSockAddr;
	CONFIG_DATA* confbuffer = NULL;
	struct timeval tv;
	int clientSock;
	int data_len = 0;
	struct stat st;	
	int isModified = 0;
	int selret = 0;
	socklen_t sockLen;
	char *readData = NULL;	

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Starting UDP server");
	if(!StartListner())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Setup Listner");
		return;
	}
	
	sockLen = sizeof(int);

	readData = (char *)malloc(sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND));
	if(!readData)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed to allocate memory.");
		return;
	}

	while(!g_CondVar)
	{
		tv.tv_sec = INFOAGENT_SERVICE_TIMEOUT_FOR_CONNECTION;
		tv.tv_usec = 0;
		fd_set servfd;
		FD_ZERO(&servfd);
		FD_SET(ListenAgentSock,&servfd);
		
		errno = 0;
		selret = select(ListenAgentSock+1,&servfd,NULL,NULL,&tv);
		if(selret == -1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Passive: select error, error string is %s",strerror(errno));
			if(errno != EINTR)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Passive infoagent exiting on select error");
				return;
			}
			else
				continue;
		}
		else if(selret > 0)
		{
			if(FD_ISSET(ListenAgentSock, &servfd))
			{
				errno = 0;
				clientSock = accept(ListenAgentSock,(struct sockaddr*)&clientSockAddr,(socklen_t*)&sockLen);
				if(clientSock < 0)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Accept Client Connection.");
					debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: accept error is %s",strerror(errno));
					continue;
				}
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: FD_ISSET failed.");
				continue;
			}
		}
		else if(selret == 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Socket Select TimedOut");
			continue;
		}
		
		memset(readData,0,sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND));
		RecvData(clientSock,readData,sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND),&data_len);

		if(data_len < (sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND)))
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Data Recv failed or read Lesser data");
			close(clientSock);
			continue;
		}
		else if(stat(FILESYNC_CONFIGURATION_FILE, &st) == -1)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Passive: filesync.conf file doesn't exists, handling onetime activity.");
			BringDownVirtualInterface(readData);
			if(!HandleOneTimeActivityPassiveServer(clientSock,selfIP,confbuffer,ActiveLBIP,VirtualIP,&selfType,readData))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Passive: HandleOneTimeActivityPassiveServer failed.");
			}
		}
		else if(selfType != -1)	
		{
			/*time_t activeMachineTime = strtol(confbuffer->current_time,NULL,10);
			if(!SyncMyTimeWithActive(confbuffer->zonename, activeMachineTime))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: failed to sync time with active node.");
			}*/
		
			if(selfType == REAL_VPN_SERVER)
			{
				if(!SyncTimeToNTP())
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Passive: SyncTimeToNTP failed.");
				}
			}
			else
				BringDownVirtualInterface(readData);
	
			if(!sendStatusPackage(clientSock,selfType,selfIP))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Passive: sendStatusPackage failed.");
				if(g_CondVar == 1)
				{
					close(clientSock);
					continue;
				}		
			}
			else
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Status successfully sent to active node.");
#if 0	
			if(IFIamPrimaryNodeRunningInactive())
			{
				debug_print(INFOAGENT_LOG_FILE,8,"I am primary in configuration, running as inactive.");
				debug_print(INFOAGENT_LOG_FILE,8,"I am getting connection from other node, means he is active.");
				PutRestartRequestInHALogs("Passive InfoAgent sending command for Pulse restart in event of other node running active and I am configured as primary.");
				if(!SendCommandToDaemon(PULSE_RESTART))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"PassiveLB: Failed to send Pulse Restart command to daemon");
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"Sent command for Pulse restart, Now i am exiting.");
					close(clientSock);
					exit(EXIT_SUCCESS);
				}
			}
#endif

			confbuffer = (CONFIG_DATA*)(readData + sizeof(CONFCOMMAND));
			//debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: InfoAgent Updating FileSync Configuration File.");
			isModified = 0;
			if(!UpdateFileSynConf(confbuffer, selfType, &isModified))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Update FileSync Configuration File");
			}
			
			if(isModified == 1 && selfType == REAL_VPN_SERVER)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Updating cluster information into shared memory.");
				if(!UpdateNodeInfoSharedMemory(confbuffer))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Update Cluster node information.");
				}
			}
	
			if(isModified == 1)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: InfoAgent Launching FileSync Daemon After Conf File Changed.");
				if(!LaunchFileSyncDaemon())
				{
					debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: Failed To Launch FileSync Daemon");
				}
			}
			//else
			//	debug_print(INFOAGENT_LOG_FILE,8,"Passive: No modifications in filesync.conf file.");
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo Agent, MyType is invalid. Restarting Pulse on system.");
			PutRestartRequestInHALogs("Passive InfoAgent sending command for Pulse restart in event of invalid node type.");
			if(!SendCommandToDaemon(PULSE_RESTART))
			{
				debug_print(INFOAGENT_LOG_FILE,8,"PassiveLB: Failed to send Pulse Restart command to daemon");
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"Passive: Sent command for Pulse restart, Now i am exiting.");
				close(clientSock);
				exit(EXIT_SUCCESS);
			}
		}
		
		close(clientSock);
	}

	debug_print(INFOAGENT_LOG_FILE,8,"PassiveInfo: InfoAgent Exiting");	
	close(ListenAgentSock);
	return;
}

bool IsPrimaryDown(char *servername)
{
	// Check if it responds to ping
	return true; 	
}

bool ParseLVSConfiguration(CONFIG_DATA *ClusterInfo,REALSERVER *SelfInfo,int *nodeCount,struct lvsService **RealServerList)
{
	struct lvsConfig config;
	int line,rc;
	int j = 0;
	int actual_nodecount = 0;
	char infName[8] = {0};
	struct lvsVirtualServer* lserv = NULL;
	char *virtInterface = NULL;
	char *ethname = NULL;
	char messageBuffer[1024] = {0};
	struct lvsService *tmpRealServerList = NULL;	

	if(!ClusterInfo || !SelfInfo)
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: ClusterInfo or SelfInfo is NULL.");
		return false;
	}

	int fd = open(CNF_FILE, O_RDONLY);
	if(fd < 0)
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: Failed to open %s For Parsing",CNF_FILE);
		return false;
	}
	
	rc = lvsParseConfig(fd, &config, &line);
	debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: lvsParseConfig returned %d, line %d",rc, line);
	if((rc != 0) || (line != 0))
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"lvsParseConfig error %d. Error on line no %d",rc, line);
		close(fd);
		return false;
	}
	/*else if(line != 0)
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: lvsParseConfig success");
		close(fd);
	}*/
	/*else
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"lvsParseConfig error. Error on line no %d",line);
                close(fd);
                return false;
	}*/

	lserv = config.virtServers + 0;
	if(lserv)
	{
		if(lserv->virtualDevice)
		{	
			virtInterface = (char *)malloc(strlen(lserv->virtualDevice));
			if(virtInterface)
			{
				strcpy(virtInterface,lserv->virtualDevice);
				ethname = strtok(virtInterface,":");
				if(!ethname)
				{
					debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: Failed to retrieve virtual interface name.");
					return false;
				}
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: Failed to retrieve virtual device name.");
			return false;
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"ActiveLB: Failed to parse lvs config.");
		return false;
	}

	debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"Virtual Interface read as %s",ethname);
	if(!strcmp(config.primaryServerName,GetInterfaceInfo(ethname)))//inet_ntoa(GetInterfaceInfo(ethname))) == 0)
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"I am primary configured and running active. its OK!");
		memcpy(ClusterInfo->ActivePrivateIP,config.primaryServerName,strlen(config.primaryServerName));
		memcpy(ClusterInfo->BackupPrivateIP,config.backupServerName,strlen(config.backupServerName));
		memcpy(ClusterInfo->primaryIP,config.primaryServerName,strlen(config.primaryServerName));
		memcpy(ClusterInfo->backupIP,config.backupServerName,strlen(config.backupServerName));
		
		primaryActive = true;
		primaryInActive = false;
		backupActive = false;
                backupInActive = true;
	}
	else if(!strcmp(config.backupServerName,GetInterfaceInfo(ethname)))//inet_ntoa(GetInterfaceInfo(ethname))) == 0)
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"I am a backup Active Node. It only Happens when Active is down.");
		debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"Checking If active really Down");
		if(IsPrimaryDown(config.primaryServerName))
		{
			memcpy(ClusterInfo->ActivePrivateIP,config.backupServerName,strlen(config.backupServerName));
			memcpy(ClusterInfo->BackupPrivateIP,config.primaryServerName,strlen(config.primaryServerName));
			memcpy(ClusterInfo->primaryIP,config.primaryServerName,strlen(config.primaryServerName));
                	memcpy(ClusterInfo->backupIP,config.backupServerName,strlen(config.backupServerName));
			
			primaryActive = false;
			primaryInActive = true;
			backupActive = true;
			backupInActive = false;
		}
		else
		{
#if 0
			debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"Primary Node %s is not Down. Sending Pulse Restart command.",config.primaryServerName);
			debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"I am a backup node running active. Lets Go to Backup Mode.");
                        PutRestartRequestInHALogs("Active InfoAgent sending command for Pulse restart");
			if(!SendCommandToDaemon(PULSE_RESTART))
                        {
                                debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Failed to send Pulse Restart command to daemon");
				return false;
                        }
                        else
			{
				debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"Sent command for Pulse restart, Now i am exiting.");
                                exit(EXIT_SUCCESS);
			}
#endif
		}
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,DEBUG_ERROR,"My IP address %s, doesn't match with primary [%s] or backup [%s] nodes configured in lvs.cf",GetInterfaceInfo(ethname),config.primaryServerName,config.backupServerName);
		return false;		
	}
		
	memcpy(ClusterInfo->ClusterVirtualIP,inet_ntoa(lserv->virtualAddress),strlen(inet_ntoa(lserv->virtualAddress)));
	debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"Cluster VIP read as %s",ClusterInfo->ClusterVirtualIP);

	memcpy(infName,ethname,strlen(ethname));
	if(virtInterface)
	{
		free(virtInterface);
	}

	ClusterInfo->num_realservers = lserv->numServers;

	sprintf(SelfInfo->IPaddress,"%s",ClusterInfo->ActivePrivateIP);
	sprintf(SelfInfo->IntfName,"%s",infName);
	SelfInfo->type = ACTIVE_LOAD_BALANCER;
	actual_nodecount = lserv->numServers;
	debug_print(INFOAGENT_LOG_FILE,DEBUG_INFO,"Node count set as %d",lserv->numServers);
	SelfInfo->num_realservers = lserv->numServers;
	strcpy(SelfInfo->ActiveIPAddress,ClusterInfo->ActivePrivateIP);  	
	strcpy(SelfInfo->VirtualIPAddress,ClusterInfo->ClusterVirtualIP);
	strcpy(SelfInfo->BackupIPAddress,ClusterInfo->BackupPrivateIP);

	debug_print(INFOAGENT_LOG_FILE,8,"ActiveLB: SHARED MEM: ActiveIPAddress %s, VirtualIPAddress %s, BackupIPAddress %s", SelfInfo->ActiveIPAddress, SelfInfo->VirtualIPAddress, SelfInfo->BackupIPAddress);
	debug_print(INFOAGENT_LOG_FILE,8,"ActiveLB:Cluster Information Read \nVirtualIp %s , ActivePrivateIP %s BackUPPrivateIP %s Interface %s\n",ClusterInfo->ClusterVirtualIP,SelfInfo->IPaddress,ClusterInfo->BackupPrivateIP,SelfInfo->IntfName);

	*RealServerList = (struct lvsService *)malloc(sizeof(struct lvsService)*actual_nodecount);
	if(*RealServerList == NULL)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLB: Memory Allocation Failure.");
		return false;
	}
	else
		tmpRealServerList = *RealServerList;

	struct lvsService *ServerList = NULL;		
	for(j = 0; j < lserv->numServers; j++)
	{
		ServerList = lserv->servers + j;
		tmpRealServerList[j].name = (char*)malloc(strlen(ServerList->name));
		if(tmpRealServerList[j].name)
			strcpy(tmpRealServerList[j].name, ServerList->name);
		memcpy(&(tmpRealServerList[j].address),&(ServerList->address),sizeof(struct in_addr));
		//strcpy((char*)&(RealServerList[j].address),(char*)&(ServerList->address));
		tmpRealServerList[j].isActive = ServerList->isActive;
		tmpRealServerList[j].port = ServerList->port;
		tmpRealServerList[j].weight = ServerList->weight;	
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLB: Real Server %d Details \n======================= \nName %s ,ISActive %d Port %d\n======================",j,tmpRealServerList[j].name,tmpRealServerList[j].isActive,tmpRealServerList[j].port);

		strcat(messageBuffer,inet_ntoa(ServerList->address));
		if(j != (lserv->numServers -1))
			strcat(messageBuffer,",");
	}

	memcpy(ClusterInfo->RealServer,messageBuffer,strlen(messageBuffer));
	memcpy(SelfInfo->RealServer,messageBuffer,strlen(messageBuffer));
	ClusterInfo->RealServerCount = strlen(messageBuffer);
	memcpy(ClusterInfo->IntfName,infName,strlen(infName));
	*nodeCount = actual_nodecount;
	lvsFreeConfig(&config);	
	return true; 
}

bool SendCommandToDaemon(char *command)
{
	int fd;
	int writtenBytes;
	fd = open(COMMAND_DAEMON_PIPE_NAME, O_WRONLY|O_NONBLOCK);
	if(fd)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Sending Command %s.",command);
		writtenBytes = write(fd,command,strlen(command));
		if(writtenBytes <= 0)
		{
			if(errno == EPIPE)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Sending Command Failed ,Peer End is Closed.");
			}
			else
				debug_print(INFOAGENT_LOG_FILE,8,"Sending Command Failed.");
			return false;	
		}
		
		close(fd);
		debug_print(INFOAGENT_LOG_FILE,8,"SendCommandToDaemon successfully sent command [%s].",command);
		return true;
	}
	else
		debug_print(INFOAGENT_LOG_FILE,8,"Failed To open Named Pipe For Sending Command To Restart FileSync.");
	return false;
}

bool LaunchFileSyncDaemon()
{
	PutRestartRequestInHALogs("InfoAgent sending command for FileSync restart");
	if(!SendCommandToDaemon(FILESYNC_DAEMON_RESTART))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Failed to send command FileSync restart to command daemon.");
		return false;
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"FileSync restart command sent.");	
		return true;
	}
}

#define MAX_READ_SIZE 				8
bool HandleHostedVirtualIPs()
{
	FILE *fp = NULL;
	char buf[MAX_READ_SIZE] = {0};
	
	if((fp = fopen(VIP_FEATURE_STATUS_FILE,"r")) != NULL) 
	{
		fread(buf,1,MAX_READ_SIZE,fp);
		if(strcmp(buf,"Enabled") == 0) 
		{
			debug_print(INFOAGENT_LOG_FILE,8,"HandleHostedVirtualIPs enabled.");
			SendCommandToDaemon(START_VIP_SERV_DAEMON);			
		}
		else 
		{
			debug_print(INFOAGENT_LOG_FILE,8,"HandleHostedVirtualIPs disabled.");
			SendCommandToDaemon(STOP_VIP_SERV_DAEMON);			
		}
		
		fclose(fp);
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"failed to open VIP_FEATURE_STATUS_FILE");	
		return false;
	}	

	return true;
}

int SendData(int s, char *data, int len)
{
	int written;
        char *ptr = NULL;
        int left;

        left = len;
        ptr = data;
	debug_print(INFOAGENT_LOG_FILE,8,"SendData needs to write %d bytes.", left);
        while(left > 0)
        {
                errno = 0;
                if((written = send(s, ptr, left, 0)) <= 0)
                {
                        if((errno != EINTR) && (errno != EAGAIN) && (errno != EWOULDBLOCK))
                        {
				debug_print(INFOAGENT_LOG_FILE,8,"SendData Error is %s",strerror(errno));
                                if(errno == ENOBUFS)
                                        written = 0;
                                else
                                        return 0;
                        }
                        else
                        {
				if(g_CondVar == 1)
					return 0;
				else
				{
                                	written = 0;
                                	continue;
				}
                        }
                }
		else
			debug_print(INFOAGENT_LOG_FILE,8,"Written %d bytes of data",written);	
                left -= written;
                ptr += written;
        }
	
	//debug_print(INFOAGENT_LOG_FILE,8,"Wrote %d bytes on sock %d.",len,s);	
        return 1;
}

void HandleResponseCommand(CONFCOMMAND* resptatusCmd)
{
#if 0
	//static int active_tics = 1;
	if(resptatusCmd->service == RESTART_YOUR_PULSE_IF_BACKUP)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Got status as Pulse running on other node also.");
		
		//if(active_tics <= 0)
		{
			if(backupActive)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Active LB: I am a backup node running active. Lets Go to Backup Mode.");
				PutRestartRequestInHALogs("Active InfoAgent sending command to restart. InfoAgent recieved status of backup node also running active.");
				if(!SendCommandToDaemon(PULSE_RESTART))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Failed to send Pulse Restart command to daemon");
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Sent command for pulse restart. Now Infoagent is exiting");
					exit(EXIT_SUCCESS);
				}	
			}
		}
		//else
		//{
		//	debug_print(INFOAGENT_LOG_FILE,8,"Active LB: Just reducing ticks count so that pulse handle this himself.");
		//	active_tics--;
		//}
	}
	else 
#endif	
	if(resptatusCmd->service == PASSIVE_INFO_SENDING_NODE_STATUS)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Passive info sent its status reply.");
	} 
}

bool PollSocket(struct pollfd *PollInfo, int iTimeoutInSeconds)
{
        bool bRetVal = false;
        
	if(iTimeoutInSeconds < 0)
                iTimeoutInSeconds = 0;
        
	time_t dtTimeout = time(NULL) + iTimeoutInSeconds;
        
	while(true)
        {
                int nRetVal = poll(PollInfo, 1 , iTimeoutInSeconds*1000);
                if(nRetVal >= 0)
                {
                        if(nRetVal > 0)
                                bRetVal = true;
                        break;
                }
                else
                {
                        if(nRetVal == EINTR)
                        {
				if(g_CondVar == 1)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Exiting on error conditions.");
					break;
				}

                                time_t CurrentTime = time(NULL);
                                if(CurrentTime >= dtTimeout)
                                        break;
                                else
                                        iTimeoutInSeconds = dtTimeout - CurrentTime;
                        }
                        else
                                break;
                }
        }

        return bRetVal;
}

bool ConnectToServer(int SendListenAgentSock, struct sockaddr_in *si_other)
{
	bool bRetVal = false;
	struct pollfd PollInfo;	

	fcntl(SendListenAgentSock, F_SETFL, O_NONBLOCK);

	PollInfo.fd = SendListenAgentSock;
	PollInfo.events = POLLOUT | POLLHUP | POLLERR;

	errno = 0;
	int nRetVal = connect(SendListenAgentSock, (struct sockaddr *)si_other, sizeof(struct sockaddr));
	if(nRetVal != 0)
	{
		if(errno == EINPROGRESS)
		{
			if(PollSocket(&PollInfo, INFOAGENT_CONNECT_TIMEOUT))
			{
				if(!(PollInfo.revents & POLLERR) && !(PollInfo.revents & POLLHUP))
				{
					if(PollInfo.revents & POLLOUT)
					{
						//debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Pollout on socket.");
						int nError = 0;
						socklen_t len = sizeof(int);
						if(!getsockopt(SendListenAgentSock, SOL_SOCKET, SO_ERROR, &nError, &len))
						{
							if(nError == 0)
							{
								//debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: No error on socket, means connected.");
								bRetVal = true;
							}
						}
						else
							debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: getsockopt failed.");
					}
				}
				else
					debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Poll returned error/hup on socket.");
			}
			else
				debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Poll call failed.");
		}
		else
			debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: ");
	}
	else
		bRetVal = true;

	return bRetVal;
}

void StartActiveLoadBalancer()
{
	REALSERVER SelfSharedInfo;
	char infName[8] = {0};
	CONFIG_DATA ServerInfost;
	int nodeCount = 0;
	struct lvsService *RealServerList = NULL;

	pthread_mutex_init(&g_NodesStatPtr_mutex,NULL);

	memset(&ServerInfost,0,sizeof(CONFIG_DATA));
	memset(&SelfSharedInfo,'\0',sizeof(REALSERVER));

	//TestFileOpen();
	//sleep(10);
	debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Start Active Load Balancer server");

	if(!ParseLVSConfiguration(&ServerInfost,&SelfSharedInfo,&nodeCount,&RealServerList))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer : Failed In Parsing LVS Configuration File.");
		return;	
	}

	memcpy(infName,ServerInfost.IntfName,sizeof(infName));
		
	getTimeZoneDetails(ServerInfost.zonename);

	if(!FillNodeInfoIntoSharedMemory(&SelfSharedInfo))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer : Failed To Fill Information Into Shared Memory");
		return;
	}

	/*if(!HandleHostedVirtualIPs())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer : HandleHostedVirtualIPs failed.");	
	}*/

	//TestFileOpen();	
	if(!UpdateFileSynConf(&ServerInfost,ACTIVE_LOAD_BALANCER,NULL))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer : Failed To Update FileSync Configuration File");
		return;
	}	
	
	if(!LaunchFileSyncDaemon())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer : Failed To Launch FileSync Daemon");
		return;
	}
	
	debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Updated FileSync Conf File and Started FileSync Daemon.");	
	debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Number of Real Servers in Cluster are %d",nodeCount);


	pthread_mutex_lock(&g_NodesStatPtr_mutex);
	g_NodesStatPtr = (STATUSNODE*)malloc(sizeof(STATUSNODE)*nodeCount);
	pthread_mutex_unlock(&g_NodesStatPtr_mutex);

	pthread_attr_t attr;
	int res = pthread_attr_init(&attr);
	if(res != 0) 
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Attribute init failed");
		return;
	}
	
	res = pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
	if(res != 0) 
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Setting detached state failed");
		return;
	}

	errno = 0;
	if(pthread_create(&activeListener, &attr, startCommandServer,(void*)ServerInfost.BackupPrivateIP) != 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: thread creation failed. error string %s. exiting.",strerror(errno));
		return;
	}

	system("/usr/bin/touch /home/fes/fescommon/state.xml > /dev/null 2>&1");
	system("/usr/bin/touch /etc/httpd/conf/httpd.conf > /dev/null 2>&1");

	struct sockaddr_in si_other;	
	int num_nodes = 0;

	memset((char *) &si_other, 0, sizeof(si_other));
	si_other.sin_family = AF_INET;
	si_other.sin_port = htons(INFOAGENT_SERVICE_PORT);

	int SendListenAgentSock = -1;
	struct lvsService *ServerList = NULL;
	CONFCOMMAND statusCmd;
	CONFCOMMAND *resptatusCmd = NULL;
	STATUSNODE *respStatus = NULL;
	char *statBuff = NULL, *confBuff = NULL;
	int recvLength = 0;
	
	/*Active InfoAgent Will Send Every Node Information Of Cluster 
	  And Expects Peer Node Status Information.*/	
	if(!RealServerList)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: RealServerList is NULL");
		return;
	}
	
	statBuff = (char*)malloc(sizeof(STATUSNODE)+sizeof(CONFCOMMAND));
	if(!statBuff)
	{	
		debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Recieve Buffer Allocation Failed.");
		return;
	}
	
	confBuff = (char*)malloc(sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND));
        if(!confBuff)
        {
                debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Send Buffer Allocation Failed.");
                return;
        }	

	int j,writeLen;
	bool connectingbackup = false;
	short backuplaststate = NO_BACKUP_STATUS;
	memset(&statusCmd,0,sizeof(CONFCOMMAND));
	statusCmd.service = ACTIVE_LOAD_BALANCER;
	memcpy(confBuff,&statusCmd,sizeof(CONFCOMMAND));
	memcpy(confBuff + sizeof(CONFCOMMAND),&ServerInfost,sizeof(CONFIG_DATA));
	CONFIG_DATA *tptr = (CONFIG_DATA *)(confBuff + sizeof(CONFCOMMAND));	

	while(!g_CondVar && (pthread_kill(activeListener,0) == 0))
	{
		num_nodes = 0;

		for(j = 0; j < nodeCount && !g_CondVar; j++)
		{
			ServerList = RealServerList + j;

			debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Sending Cluster Configuration Data to server %d at [%s], MyIP [%s]",
					j,inet_ntoa(ServerList->address),GetInterfaceInfo(infName))//inet_ntoa(GetInterfaceInfo(infName)));

			if(!strcmp(inet_ntoa(ServerList->address),ServerInfost.ActivePrivateIP))
			{
				//debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Real Server Address matches with ActiveIP.");
				if(num_nodes < nodeCount)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Adding Self Entry at index [%d].",num_nodes);
					pthread_mutex_lock(&g_NodesStatPtr_mutex);
						getNodeStatusDetail(g_NodesStatPtr+num_nodes,ACTIVE_LOAD_BALANCER,ServerInfost.ActivePrivateIP);
					pthread_mutex_unlock(&g_NodesStatPtr_mutex);
					num_nodes++;
				}
				continue;
			}
		
			connectingbackup = false;
			if(!strcmp(inet_ntoa(ServerList->address),ServerInfost.BackupPrivateIP))
			{
				//debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: I am connecting to backup server %s",inet_ntoa(ServerList->address));
				connectingbackup = true;	
			}

			SendListenAgentSock = socket(PF_INET,SOCK_STREAM,0);
			if(SendListenAgentSock  < 0)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Failed To Open Socket for sending cluster info.");
				debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Error string is %s",strerror(errno));
				continue;
			}
			
			si_other.sin_addr = ServerList->address;

			debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Sending Cluster Information Data to Real Server %s"
					,inet_ntoa(si_other.sin_addr));

			// use poll here.
			//if(connect(SendListenAgentSock,(struct sockaddr *)&si_other, sizeof(struct sockaddr)) < 0)
			if(!ConnectToServer(SendListenAgentSock, &si_other))
			{
				if(g_CondVar == 1)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Active, Exit condition is set");	
                                        continue;
				}
				
				debug_print(INFOAGENT_LOG_FILE,8,"Active Failed To Connect Peer End.");
				if(errno == ETIMEDOUT)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"connect timeout");
				}
				else if(errno == EINTR)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Got some signal while connecting.");
					if(g_CondVar == 1)
						continue;	
				}
				else if(errno == ECONNREFUSED)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"got connection refused from other end.");
				}
				else if(errno == EISCONN)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"this socket is already connected.");
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Error string while connecting is %s",strerror(errno));
				}

				if(connectingbackup && (backuplaststate != BACKUP_DOWN))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Backup is inactive, setting down.");
					SetbackupNodeStatus(BACKUP_DOWN);
					backuplaststate = BACKUP_DOWN;
				}	
			} 
			else
			{
				setsockblocking(SendListenAgentSock);
				if(connectingbackup && (backuplaststate != BACKUP_ACTIVE))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Backup is active again, setting up");
					SetbackupNodeStatus(BACKUP_ACTIVE);
                                        backuplaststate = BACKUP_ACTIVE;
				}

				sprintf(tptr->current_time,"%u",(unsigned)time(NULL));
				//debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Time Sent from Active Load Balancer %s",tptr->current_time);	
				//debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: connected to %s",inet_ntoa(si_other.sin_addr));
				writeLen = sizeof(CONFIG_DATA)+sizeof(CONFCOMMAND);	
				if(!SendData(SendListenAgentSock, confBuff, writeLen))
				{
					debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: SendData failed.");
					close(SendListenAgentSock);
                                        continue;	
				}

				//debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Wrote %d Bytes Of Configuration Data",writeLen);
			
				int totalread_done = 0;
				memset(statBuff,'\0',sizeof(CONFCOMMAND));	
				while(true)
				{	
					recvLength = 0;	
					if(RecvData(SendListenAgentSock,statBuff,(sizeof(STATUSNODE)+sizeof(CONFCOMMAND))-totalread_done ,&recvLength) > 0)
					{
						totalread_done = totalread_done + recvLength;
						if(totalread_done == (sizeof(STATUSNODE)+sizeof(CONFCOMMAND)))
						{
							resptatusCmd = (CONFCOMMAND *)statBuff;
							if(resptatusCmd)
                                                        {
								debug_print(INFOAGENT_LOG_FILE,8,"checking response action.");
                                                                HandleResponseCommand(resptatusCmd);
                                                        }
							
							respStatus = (STATUSNODE *)(statBuff + sizeof(CONFCOMMAND));
							debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Got Status Msg as %x From Node [%s][cpu %s] [mem %s][secmem %s][uptime %s]",resptatusCmd->service,respStatus->nodeIP,respStatus->cpu,respStatus->mem,respStatus->secMem,respStatus->sysUpTime);
							if(num_nodes < nodeCount)
							{
								pthread_mutex_lock(&g_NodesStatPtr_mutex);
								memcpy(g_NodesStatPtr+num_nodes,respStatus,sizeof(STATUSNODE));
								pthread_mutex_unlock(&g_NodesStatPtr_mutex);
								num_nodes++;
								break;
							}
							else
							{
								debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: Node count already exceed.");
								break;
							}
						}
						else if(totalread_done == sizeof(CONFCOMMAND))
						{
							debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: RecvData got just CONFCOMMAND. Other node is probably active running.");
							resptatusCmd = (CONFCOMMAND *)statBuff;
							if(resptatusCmd)
							{
								HandleResponseCommand(resptatusCmd);	
							}
						}	
						else
						{
							debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Got Data less than the Expected %d Expected was %d",(int) recvLength,(int)(sizeof(STATUSNODE)+sizeof(CONFCOMMAND)));
						}
					}
					else
					{
						debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Read failed/close.");	
						break;
					}
				}
			}
				
			if(SendListenAgentSock >= 0)
				close(SendListenAgentSock);
			if(g_CondVar != 1)
				sleep(2);
		}
		
		debug_print(INFOAGENT_LOG_FILE,8,"ACTIVE: System info added for [%d] nodes",num_nodes);
		g_NumNodes = num_nodes;

		if(g_CondVar != 1)
			sleep(INFOAGENT_HEARTBEAT_INTERVAL);
	}
	
	debug_print(INFOAGENT_LOG_FILE,8,"ActiveLoadBalancer: Finished Execution. Exiting");	
	exit(EXIT_SUCCESS);	
}

void HandleSigTerm(int sigNum)
{
	//debug_print(INFOAGENT_LOG_FILE,8,"Sigterm Signal Handler Called. Setting exit condition.");
	g_CondVar = 1;
	ListenAgentSock = 0;	
	close(ListenAgentSock);
}

bool CreateNodeInfoSharedMemory()
{
	int shmid = -1;
	shmSem = create_sem();
	if(shmSem == -1)
	{	
		debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Failed To Create Semaphore");
		return false;
	}	
			
	sem_get_lock(shmSem);
	shmid = shmget(SHMKEY_NODEINFO,sizeof(REALSERVER),IPC_CREAT|IPC_EXCL|0666);
	if(shmid == -1)
	{
		if(errno == EEXIST)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Deleting Already Existing Shared memory");
			int temp = shmget(SHMKEY_NODEINFO,0,IPC_CREAT|0666);
			if(shmctl(temp,IPC_RMID,0) == -1)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Failed to Delete already Existing Memory");
				sem_set_unlock(shmSem);
				return false;
			}

			shmid = shmget(SHMKEY_NODEINFO,sizeof(REALSERVER),IPC_CREAT|IPC_EXCL|0666);
			if(shmid == -1)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Failed To Get Shared Memory,Some process alreay attached.");
				sem_set_unlock(shmSem);	
				return false;
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Successfully Created Shared Memory After Removing Existing One");
				sem_set_unlock(shmSem);
				return true;
			}	
		}
		
		debug_print(INFOAGENT_LOG_FILE,8,"CreateNodeInfoSharedMemory::Failed To Get Shared Memory.");
		sem_set_unlock(shmSem);
		return false;
	}

	sem_set_unlock(shmSem);
	return true;
}

void startInfoAgent(char* LBROLE)
{
	struct stat st;

	signal(SIGTERM,HandleSigTerm);
	signal(SIGPIPE,SIG_IGN);

	if(!CreateNodeInfoSharedMemory())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"startInfoAgent:: Failed to Create NodeInfoShared Memory.");
		return;
	}
	
	if(stat(CNF_FILE,&st) != 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"startInfoAgent:: No lvs conf file. Start UDP server In case of REAL-VPN-SERVER.");
		StartPassiveServer();
	}
	else
	{
		if(LBROLE != NULL)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Role argument read as %s", LBROLE);
			if(strstr(LBROLE, "Active") != NULL)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"startInfoAgent:: Starting ACTIVE Mode infoAgent on ACTIVE_LOAD_BALANCER.");
				StartActiveLoadBalancer();
			}
			else
			{
				debug_print(INFOAGENT_LOG_FILE,8,"startInfoAgent:: Starting UDP Server In case of STANDBY_LOAD_BALANCER.");	
				StartPassiveServer();
			}
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"No role argument provided.");
			debug_print(INFOAGENT_LOG_FILE,8,"startInfoAgent:: Starting UDP Server In case of STANDBY_LOAD_BALANCER.");
			StartPassiveServer();
		}
	}
}

bool SetbackupNodeStatus(short status)
{
	REALSERVER *selfInformation = NULL;
	void *pttr = NULL;
        int shmid;

        sem_get_lock(shmSem);

        shmid = shmget(SHMKEY_NODEINFO,0,IPC_CREAT|0666);
        if(shmid == -1)
        {
                debug_print(INFOAGENT_LOG_FILE,8,"Failed To Fill Shared Memory With Node Information");
                sem_set_unlock(shmSem);
                return false;
        }
        else
        {
                debug_print(INFOAGENT_LOG_FILE,8,"Updating Backup Node Stauts into Shared mem");
                pttr = shmat(shmid,NULL,0);
                if(pttr)
                {
                        selfInformation = (REALSERVER*)pttr;
			if(selfInformation)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"Backup node existing status %d, new status %d",
						selfInformation->isbackupActive,status);
				selfInformation->isbackupActive = status;//BACKUP_DOWN;						
			}
	
			shmdt(pttr);
		}
	}

	sem_set_unlock(shmSem);
        return true;
}

bool UpdateNodeInfoSharedMemory(CONFIG_DATA* ClusterInfo)
{
	REALSERVER* selfInformation = NULL;
        void* pttr = NULL;
        int shmid;

        sem_get_lock(shmSem);

	errno = 0;
        shmid = shmget(SHMKEY_NODEINFO, 0, 0666);
        if(shmid == -1)
        {
                debug_print(INFOAGENT_LOG_FILE,8,"Failed To update HA shared memory with node information, shmget failed. error-string %s", strerror(errno));
                sem_set_unlock(shmSem);
                return false;
        }
        else
        {
		errno = 0;
                pttr = shmat(shmid, NULL, 0);
                if(pttr)
                {
                        selfInformation = (REALSERVER*)pttr;
			if(selfInformation)
			{		
				strcpy(selfInformation->ActiveIPAddress, ClusterInfo->ActivePrivateIP);
				strcpy(selfInformation->BackupIPAddress, ClusterInfo->BackupPrivateIP);
				strcpy(selfInformation->VirtualIPAddress, ClusterInfo->ClusterVirtualIP);
				memcpy(selfInformation->RealServer, ClusterInfo->RealServer, strlen(ClusterInfo->RealServer));
				selfInformation->num_realservers = ClusterInfo->num_realservers;			
			}

			shmdt(pttr);
		}
		else
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Updating node information into shared memory failed, shmat failed. error-string %s", strerror(errno));
			sem_set_unlock(shmSem);
                	return false;	
		}
	}

	sem_set_unlock(shmSem);
        return true;
}

bool FillNodeInfoIntoSharedMemory(REALSERVER *SelfSharedInfo) 
{
	REALSERVER* selfInformation = NULL;
	void* pttr = NULL;
	int shmid;

	sem_get_lock(shmSem);

	shmid = shmget(SHMKEY_NODEINFO,0,IPC_CREAT|0666);
	if(shmid == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Failed To Fill Shared Memory With Node Information");
		sem_set_unlock(shmSem);
		return false;
	}
	else
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Writing Node Information into Shared mem");
		pttr = shmat(shmid,NULL,0);
		if(pttr)
		{
			selfInformation = (REALSERVER*)pttr;
			memset(selfInformation,'\0',sizeof(REALSERVER));
			
			strcpy(selfInformation->IntfName,SelfSharedInfo->IntfName);
			strcpy(selfInformation->IPaddress,SelfSharedInfo->IPaddress);
			strcpy(selfInformation->ActiveIPAddress,SelfSharedInfo->ActiveIPAddress);
			strcpy(selfInformation->BackupIPAddress,SelfSharedInfo->BackupIPAddress);
			strcpy(selfInformation->VirtualIPAddress,SelfSharedInfo->VirtualIPAddress);
			
			memcpy(selfInformation->RealServer,SelfSharedInfo->RealServer,strlen(SelfSharedInfo->RealServer));
			
			selfInformation->type = SelfSharedInfo->type;
			selfInformation->num_realservers = SelfSharedInfo->num_realservers;
			selfInformation->isbackupActive = NO_BACKUP_STATUS;
			
			debug_print(INFOAGENT_LOG_FILE,8,"Node Information Written: InterFace %s IPAddress %s ActiveIPAddress %s:%s NodeType %d ClusterVIP %s",selfInformation->IntfName,selfInformation->IPaddress,selfInformation->ActiveIPAddress,SelfSharedInfo->ActiveIPAddress,selfInformation->type,selfInformation->VirtualIPAddress);
			debug_print(INFOAGENT_LOG_FILE,8,"Backup Node added as %s v/s %s",selfInformation->BackupIPAddress,SelfSharedInfo->BackupIPAddress);
			shmdt(pttr);
		}
	}
	
	sem_set_unlock(shmSem);
	return true;
}

void getOtherInstancePIDs(int *parentPID,int *childPID)
{
	int fd;
	char buffer[50] = {0};
	char *cpid,*ppid ;
	fd = open(INFOAGENT_PID_FILE,O_RDONLY,0666);
	if(fd < 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Failed To Open PID File For Reading.");
		return;
	}
	else
	{
		int readBytes = read(fd,buffer,sizeof(buffer));
		if(readBytes > 0)
		{
			strtok(buffer,"=");
			ppid =  strtok(NULL,"&");
			strtok(NULL,"=");
			cpid =  strtok(NULL,"=");
			debug_print(INFOAGENT_LOG_FILE,8,"Child Pid is %s and Parent Pid is %s.",cpid,ppid);
			if(ppid)
				*parentPID = atoi(ppid);
			if(cpid)
				*childPID = atoi(cpid);
		}
		/*syntax is PARENT_ID=&CHILD_ID=*/
	}
	close(fd);
}

bool stopAlreadyRunningInstances()
{
	int parentPID,childPID;
	/*if((*lockFd = open(INFOAGENT_LOCK_FILE,O_CREAT|O_RDWR, 0666))  < 0)
	  {
	  debug_print(INFOAGENT_LOG_FILE,8,"Failed To Open InfoAgent Lock File.");
	  return false;
	  }

	  errno = 0;	
	  if(flock(*lockFd, LOCK_EX|LOCK_NB) < 0) 
	  {

	  if(errno == EWOULDBLOCK)
	  {
	  debug_print(INFOAGENT_LOG_FILE,8,"Got EWOULDBLOCK error, means Instance of filesync already running.");
	  }
	  */
	//debug_print(INFOAGENT_LOG_FILE,8,"Instances Of InfoAgent Already Running. flock error is %s",strerror(errno));		
	getOtherInstancePIDs(&parentPID,&childPID);
	debug_print(INFOAGENT_LOG_FILE,8,"Existing Instance of infoagent parent pid [%d], child pid [%d]",parentPID,childPID);

	if(childPID > 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"stopAlreadyRunningInstances, killing child pid %d",childPID);
		short retry = INFOAGENT_KILL_RETRY_ATTEMTPS;
		while(retry)
		{
			errno = 0;
			if(kill(childPID,0) == 0)
			{
				errno = 0;
				debug_print(INFOAGENT_LOG_FILE,8,"Process with pid %d exists, killing it with sigterm.",childPID);
				if(kill(childPID,SIGTERM) == -1)
				{
					if(errno != ESRCH)
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Failed to term pid %d,\
								Error String %s",childPID,strerror(errno));
						return false;
					}
					else
					{
						debug_print(INFOAGENT_LOG_FILE,8,"PID %d is already dead",childPID);
						break;
					}
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"SIGTERM has been sent to child pid [%d], waiting for it to exit.",childPID);
					sleep(2);
					retry--;
					if(!retry)
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Can't stop existing running Infoagent using sigterm after %d\
								tries. Now trying with SIGKILL.",10);
						if(kill(childPID,SIGKILL) == -1)
						{
							if(errno != ESRCH)
							{
								debug_print(INFOAGENT_LOG_FILE,8,"Failed to kill pid %d,\
										Error String %s",childPID,strerror(errno));
								return false;
							}
							else
							{
								debug_print(INFOAGENT_LOG_FILE,8,"PID %d is already dead",childPID);
								break;
							}
						}
						else
							break;
					}
				}
			}
			else if(errno == ESRCH)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"No such Infoagent child process exists with pid [%d]",childPID);
				break;
			}
		}
	}
	else
		debug_print(INFOAGENT_LOG_FILE,8,"child process read is invalid pid: [%d].",childPID);
	
	if(parentPID > 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"stopAlreadyRunningInstances, killing child pid %d",parentPID);
		short retry = INFOAGENT_KILL_RETRY_ATTEMTPS;
		while(retry)
		{
			errno = 0;
			if(kill(parentPID,0) == 0)
			{
				errno = 0;
				debug_print(INFOAGENT_LOG_FILE,8,"Process with pid %d exists, killing it with sigterm.",parentPID);
				if(kill(parentPID,SIGTERM) == -1)
				{
					if(errno != ESRCH)
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Failed to term pid %d,\
								Error String %s",parentPID,strerror(errno));
						return false;
					}
					else
					{
						debug_print(INFOAGENT_LOG_FILE,8,"PID %d is already dead",parentPID);
						break;
					}
				}
				else
				{
					debug_print(INFOAGENT_LOG_FILE,8,"SIGTERM has been sent to child pid [%d], waiting for it to exit.",parentPID);
					sleep(2);
					retry--;
					if(!retry)
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Can't stop existing running Infoagent using sigterm after %d\
								tries. Now trying with SIGKILL.",10);
						if(kill(parentPID,SIGKILL) == -1)
						{
							if(errno != ESRCH)
							{
								debug_print(INFOAGENT_LOG_FILE,8,"Failed to kill pid %d,\
										Error String %s",parentPID,strerror(errno));
								return false;
							}
							else
							{
								debug_print(INFOAGENT_LOG_FILE,8,"PID %d is already dead",parentPID);
								break;
							}
						}
						else
							break;
					}
				}
			}
			else if(errno == ESRCH)
			{
				debug_print(INFOAGENT_LOG_FILE,8,"No such Infoagent child process exists with pid [%d]",parentPID);
				break;
			}
		}
	}
	else
		debug_print(INFOAGENT_LOG_FILE,8,"parent process read is invalid pid: [%d].",parentPID);

	return true;
	
	/*}
	  else
	  {
	  debug_print(INFOAGENT_LOG_FILE,8,"No Other Instances Of InfoAgent Running");
	  return true;
	  }*/
}

void saveProcessID()
{
	char command[128] = {0};
	//int ppid = getppid();
	int ppid = getppid();
	int pid = getpid();
	/*syntax is PARENT_ID=&CHILD_ID=*/
	debug_print(INFOAGENT_LOG_FILE,8,"Parent PID %d Child PID %d",ppid,pid);
	sprintf(command,"echo \"PARENT_ID=%d&CHILD_ID=%d\" > %s",ppid,pid,INFOAGENT_PID_FILE);
	debug_print(INFOAGENT_LOG_FILE,8,"Save Pid Command is %s",command);
	system(command);
}

void ParentSignalHandler(int sigNum)
{
	//debug_print(INFOAGENT_LOG_FILE,8,"Parent Signal Handler Called");
	//flock(lockFd,LOCK_UN);
	//close(lockFd);
}

void getTimeZoneDetails(char *zonename)
{
	char filename[256];
	struct stat fstat;
	int status;

	errno = 0;
	status = lstat("/etc/localtime", &fstat);
	if(status == -1)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"lstat failed. Error no %d, Error String %s",errno,strerror(errno));
		return;
	}

	if(S_ISLNK(fstat.st_mode))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"reading link %s","/etc/localtime");
		int nSize = readlink("/etc/localtime",filename,256);
		if(nSize > 0)
		{
			filename[nSize] = 0;
			debug_print(INFOAGENT_LOG_FILE,8,"filename read as %s",filename);
			char *ptr = strstr(filename,"zoneinfo");
                        if(ptr)
                                strcpy(zonename,ptr + strlen("zoneinfo/"));
                        else
				strcpy(zonename,filename+strlen("../usr/share/zoneinfo/"));
		}
	}
	else if(S_ISREG(fstat.st_mode))
	{	
		debug_print(INFOAGENT_LOG_FILE,8,"reading regular file");
		time_t t = time(NULL);
		struct tm lt = {0};

		localtime_r(&t, &lt);	
		strcpy(zonename,lt.tm_zone);		
	}
	
	debug_print(INFOAGENT_LOG_FILE,8,"Time Zone Read As %s",zonename);	
}

int redirect(const int descriptor, const char *const device, const int flags)
{
        int fd, result, saved_errno;

        /* Check for invalid parameters. */
        if(descriptor == -1 || !device || !*device)
                return errno = EINVAL;

        saved_errno = errno;

        /* Open the device. */
        do
        {
                fd = open(device, flags);
        }while(fd == -1 && errno == EINTR);

        if(fd == -1)
                return errno;

        /* Did we get lucky, and got the desired descriptor? */
        if(fd == descriptor)
        {
                errno = saved_errno;
                return 0;
        }

        /* Duplicate to the desired descriptor. */
        do{
                result = dup2(fd, descriptor);
        } while (result == -1 && errno == EINTR);

        if(result == -1)
        {
                saved_errno = errno;
                do {
                        result = close(fd);
                } while (result == -1 && errno == EINTR);
                return errno = saved_errno;
        }

        /* Close the unneeded descriptor. */
        do {
                result = close(fd);
	} while (result == -1 && errno == EINTR);
        /* This time we ignore that exit status;
 *          *      * the redirection is done, and this was just
 *                   *           * a temporary descriptor.
 *                            *               */

        /* Return success. */
        errno = saved_errno;
        return 0;
}
	
void dodaemon()
{
        pid_t pid, sid;

        pid = fork();
        if(pid < 0)
        {
                debug_print(INFOAGENT_LOG_FILE,8,"Daemon creation fork Failed, exiting");
                exit(EXIT_FAILURE);
        }

        if(pid > 0)
        {
                exit(EXIT_SUCCESS);
        }

        umask(0);

        sid = setsid();
        if(sid < 0)
        {
                debug_print(INFOAGENT_LOG_FILE,8,"Daemon creation setsid failed, exiting");
                exit(EXIT_FAILURE);
        }
#if 1
        /* Change the current working directory */
        if ((chdir("/home/fes/")) < 0) 
	{
		debug_print(INFOAGENT_LOG_FILE,8,"chdir to fes dir. failed.");
                /* Log any failure here */
                exit(EXIT_FAILURE);
        }
#endif

        /* Redirect standard input, output and error to /dev/null.
 *  *          * If an error occurs, abort with exit status.. say, 125. */
        if(redirect(STDIN_FILENO,  "/dev/null", O_RDONLY))
        {
                char msg[256] = {0};
                sprintf(msg,"redirect of STDIN to /dev/null failed with error %s.",strerror(errno));
		debug_print(INFOAGENT_LOG_FILE,8,"%s",msg);
                exit(125);
	}

        if(redirect(STDOUT_FILENO, "/dev/null", O_WRONLY))
        {
                char msg[256] = {0};
                sprintf(msg,"redirect of STDIN to /dev/null failed with error %s.",strerror(errno));
		debug_print(INFOAGENT_LOG_FILE,8,"%s",msg);
                exit(125);
        }

        if(redirect(STDERR_FILENO, "/dev/null", O_WRONLY))
        {
                char msg[256] = {0};
                sprintf(msg,"redirect of STDIN to /dev/null failed with error %s.",strerror(errno));
		debug_print(INFOAGENT_LOG_FILE,8,"%s",msg);
                exit(125);
        }

        /*close(STDIN_FILENO);
 *         close(STDOUT_FILENO);
 *                 close(STDERR_FILENO);*/
}

bool IsNodeInMaintainceMode()
{
	struct stat st;
	if(!stat(HA_UPGRADE_MODE_STATUS_FILE, &st))
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Node upgrade file exists. Node is in maintaince mode.");
		return true;
	}
	else
		return false;
}
	
int main(int argc,char** argv)
{
	pid_t childPID;
	int maxsigfaultsallowd = 0;

	if(IsNodeInMaintainceMode())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Node is in maintaince mode. Exiting.");
		exit(EXIT_SUCCESS);	
	}
	
	dodaemon();
	//int lockFd;
	system("/usr/bin/touch /home/fes/logs/infoagent.log > /dev/null 2>&1");
	if(!stopAlreadyRunningInstances())
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Info Agent Failed To Start");
		exit(EXIT_SUCCESS);
	}

	if((childPID = fork()) < 0)
	{
		debug_print(INFOAGENT_LOG_FILE,8,"Info Agent start failed in Fork.");
		exit(EXIT_SUCCESS);
	}
	else
	{
		if(childPID == 0)
		{
			debug_print(INFOAGENT_LOG_FILE,8,"Start Agent child Process.");
			saveProcessID();
			system("/usr/bin/rm -rf /home/fes/filesync.conf > /dev/null 2>&1");

			struct rlimit lim;
			lim.rlim_cur = RLIM_INFINITY;
			lim.rlim_max = RLIM_INFINITY;
			setrlimit(RLIMIT_CORE, &lim);			
			
			startInfoAgent(argv[1]);
			debug_print(INFOAGENT_LOG_FILE,8,"Infoagent child pid [%d] exiting.",getpid());
			exit(EXIT_SUCCESS);
		}
		else if(childPID > 0)
		{
			int status;
			int no_times_child_restarted = 0;
			signal(SIGTERM,SIG_IGN);

			while(1)
			{
				errno = 0;
				int cpid = wait(&status);
				if(cpid == -1)
				{
					debug_print(INFOAGENT_LOG_FILE,8,"Wait call failed with error %s. Parent exiting",strerror(errno));
					break;
				}
				else
				{
					if(WIFEXITED(status))
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Child process [%d] exited properly, by calling exit or _exit or returning.",cpid);
					}

					if(WIFSIGNALED(status))
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Child process [%d] got exited with signal %d",cpid,WTERMSIG(status));
						if(WTERMSIG(status) == 11 || WTERMSIG(status) == 6)
						{
							if(maxsigfaultsallowd == 10)
							{
								debug_print(INFOAGENT_LOG_FILE,8,"Exiting, Max allowed sigfaults for child has reached.");
								exit(EXIT_FAILURE);
							}
							else
							{
								debug_print(INFOAGENT_LOG_FILE,8,"Child sigfaulted for %d no. of times cont.", maxsigfaultsallowd);
								maxsigfaultsallowd++;
							}
						}
						else
							maxsigfaultsallowd = 0;
					}

					if(WIFSTOPPED(status))
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Child process [%d] got exited with STOP signal, Parent exiting");
						exit(EXIT_SUCCESS);
					}

					int rets = WEXITSTATUS(status);
					debug_print(INFOAGENT_LOG_FILE,8,"Child exited, had pid [%d], exit status [%d].",cpid,rets);
					if(WIFSIGNALED(status) && (WTERMSIG(status) != SIGTERM) && 
							(WTERMSIG(status) != SIGINT) && (WTERMSIG(status) != SIGKILL))
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Child exited with error. Needs restart.");
						if(no_times_child_restarted < MAX_RETRY_TO_RESTART_INFOAGENT)
						{
							if((childPID = fork()) < 0)
							{
								debug_print(INFOAGENT_LOG_FILE,8,"Info Agent start again failed in Forking a kid. %s",
										strerror(errno));
								exit(EXIT_SUCCESS);
							}
							else
							{
								if(childPID == 0)
								{
									no_times_child_restarted++;
									PutRestartRequestInHALogs("Infoagent got restarted after improper exit");
									debug_print(INFOAGENT_LOG_FILE,8,"Started InfoAgent child Process after improper exit.");
									saveProcessID();
									system("/usr/bin/rm -rf /home/fes/filesync.conf > /dev/null 2>&1");

									struct rlimit lim;
									lim.rlim_cur = RLIM_INFINITY;
									lim.rlim_max = RLIM_INFINITY;
									setrlimit(RLIMIT_CORE, &lim);

									startInfoAgent(argv[1]);
									exit(EXIT_SUCCESS);
								}
							}
						}
						else
						{
							debug_print(INFOAGENT_LOG_FILE,8,"Parent infoagent exiting after retrying after enough retries of infoagent child.");
							PutRestartRequestInHALogs("CRITICAL: Infoagent exiting after maximum retry attempts");
							exit(EXIT_SUCCESS);
						}
					}
					else
					{
						debug_print(INFOAGENT_LOG_FILE,8,"Child process properly exited.");
						exit(EXIT_SUCCESS);
					}
				}
			}
			
			exit(EXIT_SUCCESS);
		}
	}
	
	return EXIT_SUCCESS;
}
