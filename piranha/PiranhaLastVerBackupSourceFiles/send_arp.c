/* send_arp.c -- send arps

This program sends out one ARP packet with source/target IP and Ethernet
hardware addresses suuplied by the user.  It compiles and works on Linux
and will probably work on any Unix that has SOCK_PACKET.

The idea behind this program is a proof of a concept, nothing more.  It
comes as is, no warranty.  However, you're allowed to use it under one
condition: you must use your brain simultaneously.  If this condition is
not met, you shall forget about this program and go RTFM immediately.

Yuri Volobuev'97
volobuev@t1.chem.umn.edu

Anyway, I've previously agreed to license it under a BSD/GPL dual license (I
believe this was for one of the LinuxHA components).  This still stands. 
I've no objections against using GPL v2 specifically.

Yuri Volobuev'2010

MODIFICATION HISTORY:
01/13/2010	Marek Grac <mgrac@redhat.com>
		Added license according to communication with author

9/29/2000       Keith Barrett <kbarrett@redhat.com>
                Added typecasts to make strict compiles happier

5/9/2001        Keith Barrett <kbarrett@redhat.com>
                Added missing include files. Updated usage display
                to include -i option. Cleaned up source code visually.

*/

#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <sys/socket.h>

#define ETH_HW_ADDR_LEN 6
#define IP_ADDR_LEN 4
#define ARP_FRAME_TYPE 0x0806
#define ETHER_HW_TYPE 1
#define IP_PROTO_TYPE 0x0800
#define OP_ARP_REQUEST 2

#define DEFAULT_DEVICE "eth0"

char usage[] = { "send_arp: sends out custom ARP packet. Yuri Volobuev '97\n\
\tusage: send_arp [-i dev] src_ip_addr src_hw_addr targ_ip_addr tar_hw_addr\n\n" };

struct arp_packet
{
  u_char targ_hw_addr[ETH_HW_ADDR_LEN];
  u_char src_hw_addr[ETH_HW_ADDR_LEN];
  u_short frame_type;
  u_short hw_type;
  u_short prot_type;
  u_char hw_addr_size;
  u_char prot_addr_size;
  u_short op;
  u_char sndr_hw_addr[ETH_HW_ADDR_LEN];
  u_char sndr_ip_addr[IP_ADDR_LEN];
  u_char rcpt_hw_addr[ETH_HW_ADDR_LEN];
  u_char rcpt_ip_addr[IP_ADDR_LEN];
  u_char padding[18];
};

void die (char *);
void get_ip_addr (struct in_addr *, char *);
void get_hw_addr (unsigned char *, char *);




int
main (int argc, char **argv)
{

  struct in_addr src_in_addr, targ_in_addr;
  struct arp_packet pkt;
  struct sockaddr sa;
  int sock;
  char *device = (char *) DEFAULT_DEVICE;

  if ((argc != 5) && (argc != 7 || strcmp (argv[1], (char *) "-i")))
    die (usage);

  sock = socket (AF_INET, SOCK_PACKET, htons (ETH_P_RARP));

  if (sock < 0)
    {
      perror ("socket");
      exit (1);
    }

  if (!strcmp (argv[1], "-i"))
    device = argv[2], argv += 2;

  pkt.frame_type = htons (ARP_FRAME_TYPE);
  pkt.hw_type = htons (ETHER_HW_TYPE);
  pkt.prot_type = htons (IP_PROTO_TYPE);
  pkt.hw_addr_size = ETH_HW_ADDR_LEN;
  pkt.prot_addr_size = IP_ADDR_LEN;
  pkt.op = htons (OP_ARP_REQUEST);

  /* per RFC2002, when sending ARP reply-type
     gratuitous arps, both the ARP sender hardware
     address *AND* ARP target hardware address are
     set to the MAC address we wish to update arp
     entries for */
  get_hw_addr (pkt.targ_hw_addr, argv[4]);
  get_hw_addr (pkt.rcpt_hw_addr, argv[2]);
  get_hw_addr (pkt.src_hw_addr, argv[2]);
  get_hw_addr (pkt.sndr_hw_addr, argv[2]);

  /* per RFC2002, gratuitous ARP's have both
     the ARP Sender Protocol Address *AND* the
     ARP Target Protocol Address set to the IP
     of the ARP cache entry we wish to update */
  get_ip_addr (&src_in_addr, argv[1]);
  get_ip_addr (&targ_in_addr, argv[1]);

  memcpy (pkt.sndr_ip_addr, &src_in_addr, IP_ADDR_LEN);
  memcpy (pkt.rcpt_ip_addr, &targ_in_addr, IP_ADDR_LEN);

  bzero (pkt.padding, 18);

  strcpy (sa.sa_data, device);

  if (sendto (sock, &pkt, sizeof (pkt), 0, &sa, sizeof (sa)) < 0)
    {
      perror ("sendto");
      exit (1);
    }

  exit (0);
}




void
die (char *str)
{

  fprintf (stderr, "%s\n", str);
  exit (1);
}



void
get_ip_addr (struct in_addr *in_addr, char *str)
{

  struct hostent *hostp;

  in_addr->s_addr = inet_addr (str);

  /* if(in_addr->s_addr == -1){  Argh! ugly! in_addr->s_addr is of type
     uint32_t so comparing unsigned to signed
     would be a bad thing, I dunno what you're
     trying to do here, methinks inet_aton()
     would be better as -1 (ff.ff.ff.ff) is
     a valid ip, (use INADDR_NONE) */
  if (in_addr->s_addr == INADDR_NONE)
    {

      if ((hostp = gethostbyname (str)))
	bcopy (hostp->h_addr, in_addr, hostp->h_length);
      else
	{
	  fprintf (stderr, "send_arp: unknown host %s\n", str);
	  exit (1);
	}
    }
}



void
get_hw_addr (unsigned char *buf, char *str)
{

  int i;
  char c, val = 0;

  for (i = 0; i < ETH_HW_ADDR_LEN; i++)
    {
      if (!(c = tolower (*str++)))
	die ((char *) "Invalid hardware address");

      if (isdigit (c))
	val = c - '0';
      else if (c >= 'a' && c <= 'f')
	val = c - 'a' + 10;
      else
	die ((char *) "Invalid hardware address");

      *buf = val << 4;
      if (!(c = tolower (*str++)))
	die ((char *) "Invalid hardware address");

      if (isdigit (c))
	val = c - '0';
      else if (c >= 'a' && c <= 'f')
	val = c - 'a' + 10;
      else
	die ((char *) "Invalid hardware address");

      *buf++ |= val;

      if (*str == ':')
	str++;
    }
}
