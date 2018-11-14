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

/*This binary will be run by LB server , when it found tht its running as a Acive LB 
**Which will get the data from the partner server, Which will provide info ,
**whether remote load balancer service is running or not
*/


/*
**  createSocket() -- Create heartbeat socket
*/

static int
createSocket (struct in_addr *addr, int port, int flags)
{

  int sock;
  struct sockaddr_in address;


  if ((sock = socket (PF_INET, SOCK_DGRAM, 0)) < 0)
    {
      printf("failed to create UDP socket: %s",strerror (errno));
      return 1;
    }

  address.sin_family = AF_INET;
  address.sin_port = htons (port);
  memcpy (&address.sin_addr, addr, sizeof (*addr));

  if (bind (sock, (struct sockaddr *) &address, sizeof (address)))
    {
      printf("failed to bind to heartbeat address: %s",strerror (errno));
      return -1;
    }

  return sock;
}


int main()
{
	struct lvsConfig config;
	int remoteFd=0;
	int rc,fd;
	int master = 0;
	if ((rc = lvsParseConfig (fd, &config, &line)))
    {
   	   fprintf (stderr, "pulse: error parsing %s at line %d: %s\n",
	       configFile,line,lvsStrerror(rc));
      return 1;
    }
	close (fd);
	if ((fd = createSocket (master ? &config.primaryServer :
			  &config.backupServer, config.heartbeatPort,
			  flags)) < 0)
    {
      fprintf (stderr,
	       "pulse: cannot create heartbeat socket. running as root?\n");
      return 1;
    }
}
