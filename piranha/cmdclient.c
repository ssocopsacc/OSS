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
#include <errno.h>
typedef struct serviceCommand{
int service;
int command;
int relay;
}CONFCOMMAND;
enum commandval{
STARTSERVICE=1,
STOPSERVICE,
RELOADSERVICE,
RESP_STARTSERVICE=20,
RESP_STOPSERVICE,
RESP_RELOADSERVICE,
RESP_IGNORED=0,
RESP_RESEND=41
};
struct __statusNode {

int NodeType;
int  status_bit;
//1= pulse running
//2= FileSync running
//4= Fes running
//8=  running
char nodeIP[32];
char cpu[8];
char mem[8];
char secMem[8];
char sysUpTime[8];
}__attribute__((__packed__));
typedef struct __statusNode STATUSNODE;

int set_Block_And_NonBlock(int sock,int isBlock)
{
    long arg;

    if((arg=fcntl(sock,F_GETFL,NULL)) < 0)
    {
        return -1;
    }
    if(!isBlock)//nonblock
    {
        arg = arg | O_NONBLOCK;//turn on
        if(fcntl(sock,F_SETFL,arg)<0)
        {
            return -1;
        }
    }
    else
    {
                arg = arg & (~O_NONBLOCK);//turn off
                if(fcntl(sock,F_SETFL,arg)<0)
                {
                        return -1;
                }
    }
    return sock;
}

int recvNonBlockData(int sockfd,char *buffer,int bffSuze,int *data_len)
{
	int rVal=-1;
	fd_set readEventSet;
 	struct timeval tv;
	int uTimeLimit=35;
    time_t uTimeout;
    socklen_t sockLen;
	uTimeout=time(NULL);
    uTimeout=uTimeout+uTimeLimit;

	set_Block_And_NonBlock(sockfd,0);

	while(1)
	{
		int valOpt=0;
		tv.tv_sec=uTimeLimit;
        tv.tv_usec=0;
        FD_ZERO(&readEventSet);
        FD_SET(sockfd,&readEventSet);
        rVal=select(sockfd+1,&readEventSet,NULL,NULL,&tv);
		if(rVal==0)
            {
                    return -1;
            }
 	else if(rVal >0)
			{
                    sockLen=sizeof(int);
                    if(getsockopt(sockfd,SOL_SOCKET,SO_ERROR,(void *)&valOpt,&sockLen)<0)
                    {
                        return -1;
                    }
                    if(valOpt)
                    {
                        return -1;
                    }
					//read data from the peer 
					//*data_len=read(sockfd,buffer,sizeof(CONFCOMMAND));
					*data_len=read(sockfd,buffer,bffSuze);
                    break;
            }
          else
            {
                  if(errno==EINTR)
                  {
                      time_t uCurrentTime=time(NULL);
                      if(uCurrentTime >=uTimeout)
                          return -1;
                      else
                          uTimeLimit=uTimeLimit-uCurrentTime;
                   }
                   else
                       return -1;
            }
	}
	//close(sockfd);

	return *data_len;
}

int relayCommandToOtherLB(CONFCOMMAND relayCmd)
{
		struct sockaddr_in si_other;
		int return_code=-1;
		int data_len;
		//int sockLen=sizeof(si_other);
		int ListenAgentSock=socket(PF_INET,SOCK_STREAM,0);
								
		memset((char *) &si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons(939);
		inet_aton("192.168.1.156",&si_other.sin_addr);
		relayCmd.relay=0;
		if(!connect(ListenAgentSock,(struct sockaddr*)&si_other,sizeof(si_other)))
		{
			write(ListenAgentSock,&relayCmd,sizeof(CONFCOMMAND));
			recvNonBlockData(ListenAgentSock,(char*)&relayCmd,sizeof(CONFCOMMAND),&data_len);	
			switch (relayCmd.command)
			{

					case RESP_STARTSERVICE:
										printf("Got response for start command\n");
										return_code=0;
										break;
					case RESP_STOPSERVICE: 
										printf("Got response for stop command\n");
										return_code=0;
										break;
					case RESP_RELOADSERVICE: 
										printf("Got response for reload command\n");
										return_code=0;
										break;
					case RESP_IGNORED:
										printf("Got response for Unknown command %x\n",relayCmd.service);
										return_code=-1;
										break;
					default:
									   printf("unknown command resp %d\n",relayCmd.service);
									   break;
			}


		}
		else{
			printf("local connect failed\n");
		}

		if(relayCmd.command)
			{
				int i=0;
				STATUSNODE* readbuffer=malloc (sizeof(STATUSNODE)*relayCmd.command );
				recvNonBlockData(ListenAgentSock,readbuffer,(sizeof(STATUSNODE)*relayCmd.command),&data_len);	
				for (;i<relayCmd.command;i++)
				{
						printf(" info we have IP %s ,UpTime%s, Mem%s, CPU%s,Type %d\n",(readbuffer+i)->nodeIP,(readbuffer+i)->sysUpTime,(readbuffer+i)->mem,(readbuffer+i)->cpu,(readbuffer+i)->NodeType);
				}
			}
		/*
		
		if (sendto(ListenAgentSock, &relayCmd, sizeof(CONFCOMMAND), 0, (struct sockaddr*)&si_other, sockLen)==-1)
		{
			printf("Failed to relay Command\n");
		}*/
		close(ListenAgentSock);
		return return_code;

}
/*
int relayCommandToOtherLB(char* IpAddrs,CONFCOMMAND* relayCmd)
{
		struct sockaddr_in si_other;
		int sockLen=sizeof(si_other);
		int ListenAgentSock=socket(PF_INET,SOCK_DGRAM,0);
								
		memset((char *) &si_other, 0, sizeof(si_other));
		si_other.sin_family = AF_INET;
		si_other.sin_port = htons(939);
		inet_aton(IpAddrs,&si_other.sin_addr);

		if (sendto(ListenAgentSock, relayCmd, sizeof(CONFCOMMAND), 0, (struct sockaddr*)&si_other, sockLen)==-1)
		{
			printf("Failed to relay Command\n");
		}
		close(ListenAgentSock);
		return 0;

}
*/
int main (int argc, char** argv)
{
	int retval=0;
	CONFCOMMAND lcmd;
	lcmd.service=0x80;
	lcmd.relay=1;
	switch(atoi(argv[1]))
	{
		case STARTSERVICE: 
					
						lcmd.command=STARTSERVICE;
						break;
					
		case STOPSERVICE: 
						
						lcmd.command=STOPSERVICE;
						break;

		case RELOADSERVICE: 
				
						lcmd.command=RELOADSERVICE;
						break;
		case 4:
					lcmd.service=0x81;
					lcmd.command=0x0;
					break;
		case 5:
					lcmd.command=5;
					break;
		defalt:
					break;



	}
	//printf("%s",argv[1])
	retval=relayCommandToOtherLB(lcmd);
	printf("Response we got is  %d %d \n",lcmd.command,retval);
	return retval;
}

