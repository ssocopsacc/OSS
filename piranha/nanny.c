/*
** nanny.c -- Monitor clustering services
**
** Red Hat Clustering Tools 
** Copyright 1999 Red Hat Inc.
**
** Author: Erik Troan <ewt@redhat.com>
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
** 09/1999      1.0 -   Erik Troan <ewt@redhat.com>
**              1.10    Mike Wangsmo <wanger@redhat.com>
**                      Original functional release
**
** 12/19/1999   1.11    Phil "Bryce" Copeland <copeland@redhat.com>
**                      Changed type casts. Removed unused header files.
** 
** 1/8/2000     1.12    Phil "Bryce" Copeland <copeland@redhat.com>
**                      Added Wengsong Zhang's patches. Changed
**                      log() to piranha_log().
**
** 2/2/2000     1.13 -  Keith Barrett <kbarrett@redhat.com>
**              1.15    Added header, comments, & history.
**                      Moved some definitions to nanny.h
**
** 2/14/2000    1.16    Keith Barrett <kbarrett@redhat.com>
**                      Added send/expect parameters
**                      Added formatting and comments
**
** 2/17/2000    1.17 -  Keith Barrett <kbarrett@redhat.com>
**              1.18    Process '\n' and '\r' in send/expect strings
**
** 2/18/2000    1.19    Keith Barrett <kbarrett@redhat.com>
**                      Fix bugs in new convert_str routine
**
** 2/22/2000    1.20 -  Keith Barrett <kbarrett@redhat.com>
**              1.24    Minor formatting changes
**                      Pass routing method switches correctly
**                      Increased size of argv[]
**
** 2/28/2000    1.25 -  Keith Barrett <kbarrett@redhat.com>
**              1.26    Fixed default send/expect strings
**                      Added suppress translation option
**                      Fixed memory violation in routing options
**                      Added support for failover services.
**                      Added type casts to make strict compiles happy
**
** 3/3/2000     1.27    Keith Barrett <kbarrett@redhat.com>
**                      Changed http test string from HEAD to GET
**
** 3/4/2000     1.28 -  Keith Barrett <kbarrett@redhat.com
**              1.32    Finished all changes and bug fixes for fos
**                      Proclaimed stable
**
** 3/7/2000     1.33    Keith Barrett <kbarrett@redhat.com>
**                      Support splat (*) as an expect string
**                      Note: known good copy of nanny after cvs corruption
**
** 6/13/2000    1.34    Keith Barrett <kbarrett@redhat.com>
**                      Put in 4/24/2000 redirection patch from Jim at
**                      <dres@lastfoot.com>
**
** 6/30/2000    1.35    Keith Barrett <kbarrett@redhat.com>
**                      Added support for UDP. Removed core dump caused
**                      by omitting all parameters. Fixed unexpected
**                      read I/O timeout by default expect string.
**                      Added --version.
**
** 9/18/2000    1.36    Philip Copeland <copeland@redhat.com>
**			Fixed logic that made nanny core dump if the timeout
**			was greater than 20 seconds (curtosy Wensong)
**			Added extra --version info
**
** 05/07/2001   1.37    Keith Barrett <kbarrett@redhat.com>
**                      Added patches from tinus@eskom.co.za (bugzilla
**                      #20974 and #24843) to fix file descriptor leak
**                      and "LoadCommand=none" error.
**
** 05/29/2001   1.38    Keith Barrett <kbarrett@redhat.com>
**                      Added test-start
**
** 6/14/2001	1.39	Philip Copeland <bryce@redhat.com>
**			fast fixup of /usr/sbin/ipvsadm to /sbin/ipvsadm
**			this is a speed fixup, it will be sorted out in
**			a define next week
**
** 6/15/2001	1.40	Philip Copeland <bryce@redhat.com>
**
** 8/27/2001	1.41	Philip Copeland <bryce@redhat.com>
**			Merged in Wensongs fwmark patchs
**
** 9/22/2001	1.42	Philip Copeland <bryce@redhat.com>
**			Added in the send_program (-e) option
**
** 10/2/2001	1.43	Philip Copeland <bryce@redhat.com>
**			Added in the weighting fix from wensong that we
**			discussed
**
** 11/21/2001	1.44	Philip Copeland <bryce@redhat.com>
**			Wensong <wensong@gnuchina.org> kindly provided
**			a cleanup patch to nanny.c that tidies up the
**			run() function and creates two new fuctions
**			adjustWeight(), and checkState()
**
** 11/26/2001	1.45	Philip Copeland <bryce@redhat.com>
**			removal of unnecessary usleep() call
**
** 11/29/2001	1.46	Philip Copeland <bryce@redhat.com>
**			Merged in wensongs patch for nanny to support
**			quiecence of a server (see man 8 nanny)
**    
** 10/15/2002           Mike McLean <mikem@redhat.com>
**                      Added regex support for expect_str 
**                      (enable w/ command line option --regex)
**
** 11/27/2005           Florin Malita <fmalita@glenayre.com>
**                      Fixed memory leak in external_check().
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
#include <syslog.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#include "globals.h"
#include "util.h"
#include "nanny.h"

#define _PROGRAM_VERSION NANNY
#define DEBUG 1

#define _(a) (a)
#define N_(a) (a)

int mx_dup_ck = MAX_DUP_CHK;
char rcvd_tbl[MAX_DUP_CHK / 8];

#define	A(bit)		rcvd_tbl[(bit)>>3]	/* identify byte in array */
#define	B(bit)		(1 << ((bit) & 0x07))	/* identify bit in byte */
#define	CLR(bit)	(A(bit) &= (~B(bit)))

static int childDead = 0;
static int gotAlarm = 0;
sigjmp_buf killYourself;
static int nextState = 0;
pid_t needsKilling = 0;
int use_udp = 0;
unsigned int fwmark = 0;

/* Default send/expect for port 80 */
static const char *http_send_str = "GET / HTTP/1.0\r\n\r\n";
static const char *http_recv_str = "HTTP";


int
shutdownDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	     struct in_addr *remoteAddr, int rport, int service_type, int fm, int udp);

int
adjustDevice (int flags, char *ipvsadm, char *virtualAddress, int port,
	      struct in_addr *remoteAddr, int rpot, char *routingMethod, int weight,
	      int fm, int udp);

int
bringUpDev (int flags, char *ipvsadm, char *virtualAddress, int port,
	    struct in_addr *remoteAddr, int rport, char *routingMethod, int weight,
	    int service_type, int fm, int udp);

char *
getExecOutput (int flags, char **argv, int timeout)
{

	pid_t child;
	int status;
	sigset_t sigs, oldSigs;
	int p[2];
	int rc;
	char buf[4096];

	sigemptyset (&sigs);
	sigaddset (&sigs, SIGTERM);
	sigaddset (&sigs, SIGINT);
	sigaddset (&sigs, SIGALRM);

	pipe (p);

	if (!(child = fork ())) {
		int stdin, stderr;

		close (p[0]);
		if (p[1] != STDOUT_FILENO) {
		        close (STDOUT_FILENO);
			dup2 (p[1], STDOUT_FILENO);
			close (p[1]);
		}

		stdin = open ("/dev/null", O_RDONLY);
		if (stdin != STDIN_FILENO) {
			close (STDIN_FILENO);
			dup2 (stdin, STDIN_FILENO);
		}
		stderr = open ("/dev/null", O_WRONLY);
		if (stderr != STDERR_FILENO) {
			close (STDERR_FILENO);
			dup2 (stderr, STDERR_FILENO);
		}

		/* Child: Unblock & return all signals to default */
 		sigfillset(&sigs);
 		sigprocmask(SIG_UNBLOCK, &sigs, NULL);
 		for (rc = 1; rc < _NSIG; rc++)
 			signal(rc, SIG_DFL);

		execvp (argv[0], argv);
		exit (1);
	}

	close (p[1]);

	alarm (timeout);

	needsKilling = child;
	sigprocmask (SIG_UNBLOCK, &sigs, &oldSigs);

	rc = waitpid (child, &status, 0);
	sigprocmask (SIG_SETMASK, &oldSigs, NULL);
	needsKilling = 0;

	if (rc < 0) {
		if (rc == EINTR)
			piranha_log (flags, (char *)
				     "unexpected return \"%s\" running the following:");
		else
			piranha_log (flags,
				     (char *) "timeout running the following:");

		logArgv (flags, argv);
		kill (child, SIGKILL);
		waitpid (child, &status, 0);
		close (p[0]);	/* Per bugzilla #20974 */
		return NULL;
	}

	if (!WIFEXITED (status) || WEXITSTATUS (status)) {
		piranha_log (flags,
			     (char *) "The following exited abnormally:");
		logArgv (flags, argv);
		close (p[0]);	/* Per bugzilla #20974 */
		return NULL;
	}

	rc = read (p[0], buf, sizeof (buf) - 1);
	if (rc >= 1)
	  buf[rc - 1] = '\0';	/* chop */
	else
	  buf[0] = '\0';
	
	close (p[0]);

	return strdup (buf);
}


static void
handleTermSignal (int signal)
{
	/* Normally, this would be an absolutely terrible idea. However, we're
	   *really* careful where we unblock signals, so this is okay :-) */
	siglongjmp (killYourself, signal);
}

static void
handleChildDied (int signal)
{
	childDead = 1;
}

static void
handleAlarm (int signal)
{
	gotAlarm = 1;
}

static void
changeState (int signal)
{
	if (signal == SIGHUP)
		nextState = STATE_NORMAL;
	else if (signal == SIGUSR1)
		nextState = STATE_DOWN;
	else if (signal == SIGUSR2)
		nextState = STATE_UP;
}

short
in_cksum (const unsigned short *addr, register int len, unsigned short csum)
{
	register int nleft = len;
	const unsigned short *w = addr;
	register unsigned short answer;
	register int sum = csum;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1) {
		sum += *w++;
		nleft -= 2;
		gotAlarm = 0;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
		sum += htons (*(const u_char *) w << 8);

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff);	/* add hi 16 to low 16 */
	sum += (sum >> 16);	/* add carry */
	answer = ~sum;		/* truncate to 16 bits */
	return (answer);
}

SSL_CTX *gctx = NULL;
void InitCTX(int flags)
{   
	const SSL_METHOD *method;
	//SSL_CTX *ctx;
	char msg[512] = {0};

	(void)SSL_library_init();
	OpenSSL_add_all_algorithms();		/* Load cryptos, et.al. */
	SSL_load_error_strings();			/* Bring in and register error messages */
	ERR_load_crypto_strings();

	method = SSLv23_client_method();
	if(method)
	{		/* Create new client-method instance */
		gctx = SSL_CTX_new(method);			/* Create new context */
		if(gctx == NULL)
		{
			//ERR_print_errors_fp(stderr);
			piranha_log (flags, (char *)
					"SSL Error: %s",
					"SSL_CTX_new failed.");
			unsigned long err = 0;
			while((err = ERR_get_error()) != 0)
			{
				ERR_error_string(err,msg);
				//m_ErrorLog.WriteLog(44,1,msg,"proSetup::DumpSSLError");
				piranha_log (flags, (char *)
                                        "SSL Error: %s",
                                        msg);
			}
			abort();
		}

		SSL_CTX_set_verify(gctx, SSL_VERIFY_NONE, NULL); 
		const long flag = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
		SSL_CTX_set_options(gctx, flag);
	}
}

/*
 * pinger --
 * 	Compose and transmit an ICMP ECHO REQUEST packet.  The IP packet
 * will be added on by the kernel.  The ID field is our UNIX process ID,
 * and the sequence number is an ascending integer.  The first 8 bytes
 * of the data portion are used to hold a BSD UNIX "timeval" struct in VAX
 * byte-order, to compute the round-trip time.
 *
 * Actually this does a lot more than just an icmp ping.  This is where the
 * send/expect business is handled.
 *                                              - mikem 14 Oct 2002
 */

int
pinger (int flags, int s, struct in_addr *whereto, int port, int timeout,
	char *send_str, char *expect_str)
{

	register struct icmphdr *icp;
	register int cc;
	int i;
	u_char outpack[0x10000] __attribute__ ((aligned (sizeof (long))));
	static int ntransmitted = 0;
	int datalen = DEFDATALEN;
	int connectSock;
	struct sockaddr_in address;
	struct pollfd pollInfo[2];
	int connectTimeout = timeout * 1000;
	sigset_t sigs, oldSigs;
	int pingTimeout = connectTimeout / 5;
	char read_buf[255];
	int read_len = 0;
	int return_status = 0;
	struct sockaddr from;
	socklen_t fromlen;

#if defined(USE_PING)
	int hlen;
	struct iphdr *ip;
#endif

	static regex_t regExpr;
	static char regCompiled = 0;
	char regError[255];

	if ( (flags & NANNY_FLAG_REGEX) && expect_str && (!regCompiled) ) {
		if ((i = regcomp (&regExpr, expect_str, REG_EXTENDED)) == 0) {
			regCompiled = 1;
		} else {
			regerror (i, &regExpr, regError, sizeof (regError));
			piranha_log (flags, (char *)
				     "Error '%s' processing expected regular expression",
				     regError);
		}
	}

	if (pingTimeout < 500)
		pingTimeout = 500;

	sigemptyset (&sigs);
	sigaddset (&sigs, SIGTERM);
	sigaddset (&sigs, SIGINT);

	memset (outpack, 0, sizeof (outpack));

	icp = (struct icmphdr *) outpack;
	icp->type = ICMP_ECHO;
	icp->code = 0;
	icp->checksum = 0;
	icp->un.echo.sequence = ntransmitted++;
	icp->un.echo.id = getpid () & 0xfff;

	CLR (icp->un.echo.sequence % mx_dup_ck);

	cc = datalen + 8;	/* skips ICMP portion */

	/* compute ICMP checksum here */
	icp->checksum = in_cksum ((unsigned short *) icp, cc, 0);

	address.sin_family = AF_INET;
	address.sin_port = htons (1025);
	address.sin_addr = *whereto;

	i = sendto (s, outpack, cc, 0, (struct sockaddr *) &address,
		    sizeof (struct sockaddr));

	if (i < 0 || i != cc) {
		return 1;
	}

	if (use_udp) {
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags, (char *)
				     "Opening UDP socket to remote service port %d...",
				     port);
		connectSock = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	} else {
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags, (char *)
				     "Opening TCP socket to remote service port %d...",
				     port);
		connectSock = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP);
	}

	if (connectSock < 0) {
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags, "Failed to create socket: %s",
				     strerror (errno));
		return 1;
	}

	address.sin_port = htons (port);

	fcntl (connectSock, F_SETFL, O_NONBLOCK);

	/* this won't succeed immediately */
	if (flags & NANNY_FLAG_VERBOSE)
		piranha_log (flags,
			     (char *) "Connecting socket to remote address...");
	connect (connectSock, (struct sockaddr *) &address, sizeof (address));

#if defined(USE_PING)
	pollInfo[0].fd = s;
	pollInfo[0].events = POLLIN;
	pollInfo[0].revents = 0;

	do {
		/* wait for a ping response */
		sigprocmask (SIG_UNBLOCK, &sigs, &oldSigs);
		i = poll (pollInfo, 1, pingTimeout);
		sigprocmask (SIG_SETMASK, &oldSigs, NULL);

		if (!i) {
			/* ping timed out -- not good */
			piranha_log (flags, "ping of %s timed out",
				     inet_ntoa (*whereto));
			return 1;
		}

		/* we got an icmp packet of some sort */
		i = sizeof (from);

		cc = recvfrom (s, outpack, sizeof (outpack), 0, &from, &i);

		ip = (struct iphdr *) outpack;
		hlen = ip->ihl * 4;

		/* Now the ICMP part */
		cc -= hlen;
		icp = (struct icmphdr *) (outpack + hlen);

		if (in_cksum ((u_short *) icp, cc, 0)) {
			icp->type = 0xff;
			continue;
		}
	}
	while (icp->type != ICMP_ECHOREPLY);
#endif

	pollInfo[0].fd = connectSock;
	pollInfo[0].events = POLLOUT;
	pollInfo[0].revents = 0;

	if (flags & NANNY_FLAG_VERBOSE)
		piranha_log (flags, (char *) "DEBUG -- Posting CONNECT poll()");

	sigprocmask (SIG_UNBLOCK, &sigs, &oldSigs);
	i = poll (pollInfo, 1, connectTimeout);
	sigprocmask (SIG_SETMASK, &oldSigs, NULL);

	if (i <= 0) {
		if (i == 0) {
			piranha_log (flags,
				     (char *) "CONNECT to %s:%d timed out",
				     inet_ntoa (*whereto), port);
		} else {
			if (flags & NANNY_FLAG_VERBOSE)
				piranha_log (flags, (char *)
					     "CONNECT poll() call to %s:%d failed: %s",
					     inet_ntoa (*whereto), port,
					     strerror (errno));
		}

		close (connectSock);
		return 1;
	}

	/* now we need that connect to finish */
	fcntl (connectSock, F_SETFL, 0);

	i =
	    connect (connectSock, (struct sockaddr *) &address,
		     sizeof (address));

	if (i) {
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags, (char *)
				     "Failed to connect %s:%d ping socket: %s",
				     inet_ntoa (*whereto), port,
				     strerror (errno));
		close (connectSock);
		return 1;
	}

	/*
	**  OK, we're connected. Now test I/O
	*/
	
	SSL *ssl = NULL;
	if(gctx)
	{
		ssl = SSL_new(gctx);
		if(ssl)
		{							/* create new SSL connection state */
			SSL_set_fd(ssl, connectSock);				/* attach the socket descriptor */
			if(SSL_connect(ssl) != 1)
			{
				char msg[512] = {0};
				unsigned long err = 0;
				while((err = ERR_get_error()) != 0)
				{
					ERR_error_string(err,msg);
					//m_ErrorLog.WriteLog(44,1,msg,"proSetup::DumpSSLError");
					piranha_log (flags, (char *)
							"SSL Error: %s",
							msg);
				}
				piranha_log (flags, (char *) "SSL error %s","SSL_connect failed.");
				SSL_free(ssl);
				close(connectSock);
				return 1;
			}
		}
		else
		{
			piranha_log (flags, (char *) "SSL error %s","SSL_new failed.");
			close(connectSock);
			return 1;
		}
	}
	else
	{
		piranha_log (flags, (char *) "SSL error %s","SSL ctx is null.");
		close(connectSock);
		return 1;
	}

	return_status = 0;

	/* UDP requires sending something in order for a response to occur */

	if (send_str) {
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags,
				     (char *) "Sending len=%d, text=\"%s\"",
				     strlen (send_str), send_str);

		if (use_udp)
			i =
			    (int) sendto (connectSock, send_str,
					  strlen (send_str), 0,
					  (struct sockaddr *) &address,
					  sizeof (address));
		else
		//	i =
		//	    (int) write (connectSock, send_str,
		//			 strlen (send_str));

		i = SSL_write(ssl, send_str, strlen (send_str));
		if (i <= 0) {
			piranha_log (flags, (char *)
				     "WRITE operation for %s:%d returned error: %s",
				     inet_ntoa (*whereto), port,
				     strerror (errno));
			return_status = 1;
		}
	}

	/*
	** String sent -- try receive
	*/

	i = 0;

	if ((return_status == 0) && ((expect_str || use_udp))) {
		read_len = 0;

		pollInfo[0].fd = connectSock;
		pollInfo[0].events = POLLIN;
		pollInfo[0].revents = 0;

		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags,
				     (char *) "DEBUG -- Posting READ poll()");

		sigprocmask (SIG_UNBLOCK, &sigs, &oldSigs);
		i = poll (pollInfo, 1, connectTimeout);
		sigprocmask (SIG_SETMASK, &oldSigs, NULL);

		if (i == 0) {
			piranha_log (flags, (char *) "READ to %s:%d timed out",
				     inet_ntoa (*whereto), port);
			return_status = 1;
		}
		/* Timeout! */

		if (i < 0) {
			piranha_log (flags, (char *)
				     "READ poll() call to %s:%d failed with err#%d: %s",
				     inet_ntoa (*whereto), port, errno,
				     strerror (errno));
			return_status = 1;
		}
		/* Error! */

		if (i > 0) {
			if (flags & NANNY_FLAG_VERBOSE)
				piranha_log (flags, (char *)
					     "DEBUG -- READ poll() completed (%d,%d)",
					     i, pollInfo[0].revents);
		}

		if (return_status == 0) {

			/*
			** OK, there is data to receive -- go get it!
			*/

			if (expect_str) {
                            if (flags & NANNY_FLAG_REGEX) 
				read_len = sizeof (read_buf) - 1;
                            else
				read_len = strlen (expect_str);
                        }
			else
				read_len = 1;	/* for UDP */

			if (read_len >= sizeof (read_buf))
				read_len = sizeof (read_buf) - 1;

			if (flags & NANNY_FLAG_VERBOSE)
				piranha_log (flags, (char *)
					     "Posting READ I/O; expecting %d character(s)...",
					     read_len);

			if (use_udp) {
				fromlen = sizeof (from);
				i =
				    (int) recvfrom (connectSock, read_buf,
						    read_len, 0, &from,
						    &fromlen);
			} else
				//i =
				//    (int) read (connectSock, read_buf,
				//		read_len);
				i = SSL_read(ssl, read_buf, read_len);

			if (i >= 0)
				if (flags & NANNY_FLAG_VERBOSE)
					piranha_log (flags, (char *)
						     "DEBUG -- READ returned %d",
						     i);

			if (i < 0) {
				piranha_log (flags, (char *)
					     "READ returned error %d:%s", errno,
					     strerror (errno));
				return_status = 1;

			} 
                        else {

				/* Got it! */

				read_buf[i] = 0;

				if (flags & NANNY_FLAG_VERBOSE) {
					piranha_log (flags, (char *)
						     "READ expected len=%d, text=\"%s\"",
						     strlen (expect_str),
						     expect_str);
					piranha_log (flags, (char *)
						     "READ got len=%d, text=%s",
						     strlen (read_buf),
						     read_buf);
				}

				if ((read_len == 1) && (*expect_str == '*')) {
					/* Wildcard */
					read_buf[0] = '*';
					read_buf[1] = 0;
					i = 1;
				}
                                if (flags & NANNY_FLAG_REGEX) {
				    if (!regCompiled || regexec (&regExpr, read_buf, 0, NULL, 0))
					return_status = 1;
                                }
                                else if (i >= read_len) {
					if (strncmp ((const char *) expect_str,
						     (const char *) read_buf,
						     read_len)) return_status =
						    1;
				} else {
					piranha_log (flags, (char *)
						     "READ from %s:%d was too short",
						     inet_ntoa (*whereto),
						     port);
					return_status = 1;
				}
			}
		}
	}

	if(ssl)
		SSL_free(ssl);
	close (connectSock);
	return return_status;
}


int
external_check (int flags, char *send_program, char *expect_str,
		struct in_addr *remoteAddr, int rport, int timeout)
{
	char *result;
	char *token = NULL;
	char tokenTemp[20];
	char temp[255];
	char *argv[40];		/* need this to build up argument list */
	char **argp = argv;
	int i = 0, res;

	if (send_program != NULL)
		strcpy (temp, send_program);

	if (send_program != NULL) {
		token = strtok (temp, " ");
	} else {
		piranha_log (flags, (char *) "No command to run\n");
		return 1;
	}

	while (token != NULL) {
		i++;
		if (strcmp (token, "%h") == 0)
			token = inet_ntoa (*remoteAddr);
		else if (strcmp (token, "%p") == 0) {
			sprintf (tokenTemp, "%d", rport);
			token = tokenTemp;
		}
		*argp++ = token;
		token = strtok (NULL, " ");
	}
	*argp++ = NULL;		/* just make sure everyone knows this is the end */

	if (flags & NANNY_FLAG_VERBOSE) {
		piranha_log (flags, (char *) "Found %d argument(s)", --i);
		piranha_log (flags, (char *) "Invoking:  %s\n", temp);
	}

	result = getExecOutput (flags, argv, timeout);

	if (flags & NANNY_FLAG_VERBOSE)
		piranha_log (flags, (char *)
			     "Got result (%s) from command sent to (%s:%d)\n",
			     result, inet_ntoa (*remoteAddr), rport);

	if ((result == NULL) && (expect_str == NULL)) {
		piranha_log (flags, (char *)
			     "Ran the external sending program. The result and expected response are both NULL! You may wish to revise your settings\n");
		return 1;
	}

	if (result == NULL) {
		piranha_log (flags, (char *)
			     "Ran the external sending program to (%s:%d) but didn't get anything back\n",
			     inet_ntoa (*remoteAddr), rport);
		return 0;
	}

	if (expect_str != NULL) {
		if (strcmp (expect_str, result) != 0) {
			piranha_log (flags, (char *)
				     "Trouble. Received results are not what we expected from (%s:%d)\n",
				     inet_ntoa (*remoteAddr), rport);
			res = 1;
		} else {
			res = 0;
		}

	} else {
		piranha_log (flags, (char *)
			     "Expect string is NULL, but the external sending program returned a non-NULL result\n");
		res = 1;
	}
	
	free(result);
	return res;
}

float
getRemoteLoad (int flags, struct in_addr *remoteAddr, int timeout,
	       char *loadCommand)
{

	char *argv[40];
	char **argp = argv;
	char *output;
	char *start, *chptr;
	float avg;

	if (strcmp (loadCommand, (char *) "none") == 0)
		/* == 0 per bugzilla #24843 */
		return -1.0;	/* nothing to see here, go home silently */

	*argp++ = loadCommand;
	*argp++ = inet_ntoa (*remoteAddr);

	if ( (strcmp (loadCommand, (char *) "ssh") == 0)  
                || (strcmp (loadCommand, (char *) "rsh") == 0) )
            *argp++ = (char *) "uptime";
            
	*argp++ = NULL;

	logArgv (flags, argv);

	output = getExecOutput (flags, argv, timeout);

	if (!output) {
		piranha_log (flags, (char *) "failed to read remote load");
		return -1.0;
	}

	start = strstr (output, "load");

	if (!start || !strchr (start, ':')) {
		piranha_log (flags, (char *) "bad load average returned: %s",
			     output);
		return -1.0;
	}

	start = strchr (start, ':') + 2;

	/* 
	 * Then, there are three load averages during the last 1, 5 and 15 
	 * minutes. We just want the one minute loadavg.
	 */
	chptr = start;
	while (*chptr && (isdigit (*chptr) || (*chptr == '.')))
		chptr++;

	if (*chptr != ',' && *chptr != ' ') {
		piranha_log (flags, (char *) "bad load average returned: %s",
			     output);
		free (output);
		return -1.0;
	}

	*chptr = '\0';

	avg = strtod (start, NULL);

	if (flags & NANNY_FLAG_VERBOSE)
		piranha_log (flags, (char *) "Loadavg of %s is %f",
			     inet_ntoa (*remoteAddr), avg);

	free (output);
	return avg;
}

int
adjustWeight (int flags, char *ipvsadm, char *virtualAddress, int port,
	      struct in_addr *remoteAddr, int rport, char *routingMethod, int weight,
	      int interval, int scale, char *loadCommand, int lastWeight)
{
	int newWeight;

	if (lastWeight < weight) {
		/* Gradually adjusting weight up to its specified server
		   after a new server is added */
		newWeight = lastWeight << 1;
		if (newWeight > weight)
			newWeight = weight;
		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags, (char *)
				     "Adjusting weight of %s:%d to %d",
				     inet_ntoa (*remoteAddr),
				     rport, newWeight);

		if (adjustDevice (flags, ipvsadm, virtualAddress,
				  port, remoteAddr, rport, routingMethod,
				  newWeight, fwmark, use_udp))
			return -1;
	} else {
		/* Querying the load information and adjusting the
		   server weight accordingly */
		float load;
		double scaleFactor = (double) weight / 2;
		/* weight difference threshold */
		float diffThresh = (float) weight / 4;

		load = getRemoteLoad (flags, remoteAddr,
				      interval,
				      loadCommand);

		if ((load >= 0.0) && (load != 1.0)) {
			if (load < 1.0) {
				newWeight = lastWeight + scaleFactor *
					pow ((double)(1.0 - load),
					     (double) 1 / 3);
				if (newWeight > scale * weight)
					newWeight = scale * weight;
			} else {
				newWeight = lastWeight - scaleFactor *
					pow ((double)(load - 1.0),
					     (double) 1 / 3);
				if (newWeight < weight)
					newWeight = weight;
			}

			if (flags & NANNY_FLAG_VERBOSE)
				piranha_log (flags,
					     (char *)
					     "Computing new weight %d based "
					     "on last weight %d and load %f",
					     newWeight, lastWeight, load);

			if (abs(newWeight - lastWeight) >= diffThresh) {
				if (flags & NANNY_FLAG_VERBOSE)
					piranha_log (flags,
						     (char *)
						     "Adjusting weight of %s:%d to %d",
						     inet_ntoa(*remoteAddr),
						     port, newWeight);

				if (adjustDevice (flags, ipvsadm,
						  virtualAddress, port,
						  remoteAddr, rport, routingMethod,
						  newWeight, fwmark, use_udp))
					return -1;

				return newWeight;
			}
		}
		/* The weight is not adjusted */
		return lastWeight;
	}

	return newWeight;
}

int
checkState (int flags, char *ipvsadm, char *virtualAddress, int port,
	    struct in_addr *remoteAddr, int rport, char *routingMethod, int weight,
	    int *isActive, sigset_t *sigs, int service_type)
{
	if (!nextState)
		return 1;

	while (nextState != STATE_NORMAL) {
		switch (nextState) {

		case STATE_UP:
			piranha_log (flags, (char *)
				     "rose-colored glasses on");

			if (!*isActive) {
				if (service_type == SERV_LVS) {
					/* Virtual Server */
					if (bringUpDev (flags, ipvsadm,
							virtualAddress, port,
							remoteAddr, rport, 
							routingMethod,
							weight, service_type,
							fwmark, use_udp))
						return -1;
				}
				*isActive = 1;
			}
			break;

		case STATE_DOWN:
			piranha_log (flags, (char *) "opaque glasses on");

			if (*isActive) {
				if (service_type == SERV_LVS) {
					/* Virtual Server */
					if (shutdownDev (flags, ipvsadm,
							 virtualAddress, port,
							 remoteAddr, rport, service_type,
							 fwmark, use_udp))
						return -1;
				}
				*isActive = 0;
			}
			break;
		}

		if (nextState != STATE_NORMAL) {
			if (flags & NANNY_FLAG_VERBOSE)
				piranha_log (flags, (char *)
					     "DEBUG -- In nextState = %d",
					     nextState);
			nextState = 0;
			sigsuspend (sigs);
		}
	}

	piranha_log (flags, (char *) "DEBUG -- removing glasses");
	nextState = 0;
	return 0;
}

int
run (int flags, char *ipvsadm, char *virtualAddress, int port,
     struct in_addr *remoteAddr, int rport, char *routingMethod, int weight,
     int interval, int countThresh, int scale, char *loadCommand,
     char *send_program, char *send_str, char *expect_str,
     int quiesce_srv, int service_type)
{

	int isActive = 0;
	int currCount = countThresh;
	int isAvail = 0;
	int isSrvUp = 0;
	int pingSocket;
	sigset_t sigs;
	time_t wakeup, now;
	int rc;
	int fos_counter = 0;
	int lastWeight = 0;

	sigemptyset (&sigs);
	sigaddset (&sigs, SIGTERM);
	sigaddset (&sigs, SIGINT);
	sigaddset (&sigs, SIGCHLD);
	sigaddset (&sigs, SIGALRM);
	sigaddset (&sigs, SIGHUP);
	sigaddset (&sigs, SIGUSR1);
	sigaddset (&sigs, SIGUSR2);
	sigprocmask (SIG_BLOCK, &sigs, NULL);

	if (flags & NANNY_FLAG_VERBOSE) {
		if (send_program)
			piranha_log (flags, (char *)
				     "Send_program len=%d, text=\"%s\"",
				     strlen (send_program), send_program);
		else
			piranha_log (flags, (char *) "Send_program is NULL");

		if (send_str)
			piranha_log (flags,
				     (char *) "Send_string len=%d, text=\"%s\"",
				     strlen (send_str), send_str);
		else
			piranha_log (flags, (char *) "Send_string is NULL");

		if (expect_str)
			piranha_log (flags, (char *)
				     "Expect_string len=%d, text=\"%s\"",
				     strlen (expect_str), expect_str);
		else
			piranha_log (flags, (char *) "Expect_string is NULL");

		if (service_type)
			piranha_log (flags,
				     (char *) "Service_type value=%d",
				     service_type);
	}

	/* Debugging output */
	if ((rc = sigsetjmp (killYourself, 1))) {	/* time to die */
		piranha_log (flags, (char *) "Terminating due to signal %d",
			     rc);

		if (needsKilling) {
			piranha_log (flags, (char *) "Killing child %d",
				     needsKilling);
			kill (needsKilling, SIGKILL);
			waitpid (needsKilling, NULL, 0);
		}

		if (isActive && service_type == SERV_LVS) {
			if (shutdownDev (flags, ipvsadm, virtualAddress, port,
					 remoteAddr, rport, service_type, fwmark, use_udp))
				exit (1);
		}

		exit (0);
	}

	signal (SIGTERM, handleTermSignal);
	signal (SIGINT, handleTermSignal);
	signal (SIGCHLD, handleChildDied);
	signal (SIGALRM, handleAlarm);
	signal (SIGUSR1, changeState);
	signal (SIGUSR2, changeState);
	signal (SIGHUP, changeState);

	sigfillset (&sigs);
	sigdelset (&sigs, SIGTERM);
	sigdelset (&sigs, SIGINT);
	sigdelset (&sigs, SIGALRM);
	sigdelset (&sigs, SIGHUP);
	sigdelset (&sigs, SIGUSR1);
	sigdelset (&sigs, SIGUSR2);

	/* we keep a single socket for pings */
	pingSocket = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);

	if (pingSocket < 0) {
		piranha_log (flags, (char *) "failed to create ping socket: %s",
			     strerror (errno));
		return 1;
	}

	do {
		/*
		** Is the service available?
		** Remember, send_program has precedence over sent text strings
		** Fortunately this code fragment simly relies on a boolean value
		** ie 'Is this service available? Yes or No?'
		*/
		if (send_program != NULL) {
			isAvail =
			    !external_check (flags, send_program, expect_str,
					     remoteAddr, rport, interval);
		} else {
			isAvail =
			    !pinger (flags, pingSocket, remoteAddr, rport,
				     interval, send_str, expect_str);
		}

		if (isAvail)
			currCount++;
		else if (service_type == SERV_FOS) {
			if (fos_counter)
				++fos_counter;
			if (fos_counter > 1) {
				piranha_log (flags, (char *)
					     "Timeout waiting for remote service -- triggering failover!");
				return 1;
			}
		}

		if (flags & NANNY_FLAG_VERBOSE)
			piranha_log (flags,
				     (char *) "avail: %d active: %d: count: %d",
				     isAvail, isActive, currCount);

		/*
		**  Now we deal with the state transistions:
		**
		**  1) service available, but not active yet.
		**  2) service active (and available)
		**  3) service was active, but no longer available
		**  4) service not available or active
		**
		**  The failover services logic for each state is almost
		**  the exact opposite as it is for virtual servers because
		**  we are monitoring the OPPOSITE computer system.
		*/

		/*
		**  Available, but inactive, and time to make it active.
		*/

		if (isAvail && !isActive && currCount >= countThresh) {
			isActive = 1;

			if (service_type == SERV_FOS) {
				/* Failover Service */
				piranha_log (flags, (char *)
					     "Remote service %s:%d is available",
					     inet_ntoa (*remoteAddr), rport);
			} else if (service_type == SERV_LVS) {
				/* Virtual Server */
				int newWeight;
				
				piranha_log (flags,
					     (char *) "%s making %s:%d available",
					     NANNY_ACTIVE_STATUS,
					     inet_ntoa (*remoteAddr), rport);

				/* compute the initial weight */
				newWeight = weight >> 5;
				if (newWeight <= 0)
					newWeight = 1;

				if (quiesce_srv && isSrvUp) {
					if (adjustDevice
					    (flags, ipvsadm,
					     virtualAddress, port,
					     remoteAddr, rport, routingMethod,
					     newWeight, fwmark, use_udp))
						return -1;
				} else {
					if (bringUpDev
					    (flags, ipvsadm,
					     virtualAddress, port,
					     remoteAddr, rport, routingMethod,
					     newWeight, service_type,
					     fwmark, use_udp))
						return -1;
					isSrvUp = 1;
				}

				lastWeight = newWeight;
			}

			/*
			**  Active, but no longer available (just went down)
			*/

		} else if (!isAvail && isActive) {
			currCount = 0;
			isActive = 0;

			if (service_type == SERV_FOS) {
				/* Failover Services */
				piranha_log (flags, (char *)
					     "Exiting due to connection failure of %s:%d",
					     inet_ntoa (*remoteAddr), rport);

				/*
				** Start service locally
				** Pulse does this now!
				*/

				return 0;
				/* Exiting tells pulse to perform a failover */

			} else if (service_type == SERV_LVS) {
				/* Virtual Services */
				piranha_log (flags, (char *)
					     "%s shutting down %s:%d due to connection failure",
					     NANNY_INACTIVE_STATUS,
					     inet_ntoa (*remoteAddr), rport);

				if (quiesce_srv && isSrvUp) {
					if (adjustDevice
					    (flags, ipvsadm,
					     virtualAddress, port,
					     remoteAddr, rport, routingMethod, 0, fwmark, use_udp))
						return -1;
				} else {
					if (shutdownDev
					    (flags, ipvsadm,
					     virtualAddress, port,
					     remoteAddr, rport, service_type, fwmark, use_udp))
						return -1;
					isSrvUp = 0;
				}
			}

			/*
			** Inactive and not available
			*/

		} else if (!isAvail && currCount) {
			currCount = 0;
			if (((flags & NANNY_FLAG_VERBOSE) != 0)
			    || (service_type == SERV_FOS))
				piranha_log (flags, (char *)
					     "No service active & available...");
			if (service_type == SERV_FOS)
				++fos_counter;
		}

		/*
		**  Adjusting the server weight every nn seconds if necessary
		**  (not applicable to failover services)
		*/

		if (service_type == SERV_LVS && isActive &&
		    (interval > 20 || currCount % (20 / interval) == 0)) {
			rc = adjustWeight (flags, ipvsadm,
					   virtualAddress, port,
					   remoteAddr, rport, routingMethod,
					   weight, interval, scale,
					   loadCommand, lastWeight);
			if (rc < 0)
				return rc;
			lastWeight = rc;
		}

		/*
		**  Monitor loop
		*/

		now = time (NULL);
		wakeup = now + interval;

		gotAlarm = 0;

		while (!gotAlarm) {
			alarm (wakeup - now);
			sigsuspend (&sigs);
			alarm (0);

			rc = checkState(flags, ipvsadm, virtualAddress,
					 port, remoteAddr, rport, routingMethod,
					 weight, &isActive, &sigs, service_type);
			if (rc < 0)
				return rc;
			else if (rc == 0) {
				currCount = countThresh;
				gotAlarm = 1;
			}

			now = time (NULL);
		}

	}
	while (1);

	/* point of no return... (unreachable) */
}

/*
**  convert_str() -- convert "\\n" characters into '\n'
*/

void
convert_str (char *in_string)
{

	char *dup_string = NULL;
	char *cur_ptr = NULL;
	int do_copy = 0;

	if (in_string)
		if (strlen (in_string) > 1)
			cur_ptr = in_string;

	if (cur_ptr) {
		while ((cur_ptr = strchr (cur_ptr, '\\'))) {

			do_copy = 0;

			switch (*(cur_ptr + 1)) {
			case '\\':
				*cur_ptr++ = '\\';
				do_copy = -1;
				break;

			case 'r':
				*cur_ptr++ = '\r';
				do_copy = -1;
				break;

			case 'n':
				*cur_ptr++ = '\n';
				do_copy = -1;
				break;

			case 't':
				*cur_ptr++ = '\t';
				do_copy = -1;
				break;

			case '\'':
				*cur_ptr++ = '\'';
				do_copy = -1;
				break;

			case '\"':
				*cur_ptr++ = '\"';
				do_copy = -1;
				break;

			default:
				break;
			}
			if (do_copy) {
				if (*cur_ptr) {
					dup_string = strdup (cur_ptr);
					strcpy (cur_ptr, (dup_string + 1));
					free (dup_string);
				}
			}
		}
	}
}

int
main (int argc, const char **argv)
{

	struct in_addr remoteAddr;
	poptContext optCon;

	int noDaemon = 0;
	int noFork = 0;
	int noRun = 0;
        int useRegex = 0;
	int teststart = 0;
	int interval = 10;
	int port = 80;
	int rport = -1;
	int weight = 1;
	int reentryTime = 0;
	int verbose = 0;
	int suppress = 0;
	int rc;
	int countThresh;
	int flags = 0;
	int scale = 10;
	int display_ver = 0;
	int quiesce_srv = 0;
	int fos_serv = 0;
	int lvs_serv = 0;
	int service_type = SERV_UNK;

	char *server = NULL;
	char *virtualAddress = NULL;
	char *routingMethod = (char *) "-m";
	char *specifiedRM;
	char *vsadmPath = (char *) IPVSADM;
	char *loadCommand = (char *) "none";
	char *send_program = NULL;
	char *send_str = NULL;
	char *expect_str = NULL;

	/* Letters taken: DIMRSTUV acnprstuvwx */

	struct poptOption options[] = {
		{"interval", 't', POPT_ARG_INT, &interval, 0,
		 N_("seconds between connection attempts")},

		{"ipvsadm", 'I', POPT_ARG_STRING, &vsadmPath, 0,
		 N_("path to ipvsadm (default " IPVSADM ")")},

		{"loadcmd", 'U', POPT_ARG_STRING, &loadCommand, 0,
		 N_
		 ("command to get remote load average (rup, rsh, ssh, none)")},

		{"method", 'M', POPT_ARG_STRING, &routingMethod, 0,
		 N_("ipvsadm routing method (default -m)")},

		{"nodaemon", 'n', 0, &noDaemon, 0,
		 N_("don't run as a daemon")},

		{"nofork", 'c', 0, &noFork, 0,
		 N_("don't fork, but do disassociate")},

		{"port", 'p', POPT_ARG_INT, &port, 0,
		 N_("port on virtual service (default 80)")},

		{"rport", 'r', POPT_ARG_INT, &rport, 0,
		 N_("port to check for availability (default 80)")},

		{"reentrytime", 'a', POPT_ARG_INT, &reentryTime, 0,
		 N_("seconds to wait for before readmitting a machine")},

		{"scale", 'S', POPT_ARG_INT, &scale, 0,
		 N_("maximum scale to weight load average by")},

		{"server", 'h', POPT_ARG_STRING, &server, 0,
		 N_("IP address of remote server")},

		{"send_program", 'e', POPT_ARG_STRING, &send_program, 0,
		 N_("Use an external program to test a service")},

		{"send_string", 's', POPT_ARG_STRING, &send_str, 0,
		 N_("string to send to port to test connectivity")},

		{"expect_string", 'x', POPT_ARG_STRING, &expect_str, 0,
		 N_("reponse string to receive after connecting to port")},

		{"regex", '\0', 0, &useRegex, 0,
		 N_("interpret expect_string as a regular expression")},

		{"suppress", 'T', 0, &suppress, 0,
		 N_("Suppress '\\' translation in send/expect strings")},

		{"quiesce_server", 'q', 0, &quiesce_srv, 0,
		 N_("quiesce server when service monitoring timeouts")},

		{"udp", 'u', 0, &use_udp, 0,
		 N_("Use UDP protocol instead of TCP")},

		{"verbose", 'v', 0, &verbose, 0,
		 N_("log debugging information")},

		{"virtaddress", 'V', POPT_ARG_STRING, &virtualAddress, 0,
		 N_("IP of virtual service")},

		{"fwmark", 'f', POPT_ARG_INT, &fwmark, 0,
		 N_("firewalling mark of virtual service")},

		{"weight", 'w', POPT_ARG_INT, &weight, 0,
		 N_("weight of remote server")},

		{"test-start", '\0', 0, &teststart, 0,
		 N_("don't actually run ipvsadm")},

		{"norun", '\0', 0, &noRun, 0,
		 N_("same as '--test-start'")},

		{"version", '\0', 0, &display_ver, 0,
		 N_("Display program version")},

		{"fos", '\0', 0, &fos_serv, 0,
		 N_("Failover Service")},

		{"lvs", '\0', 0, &lvs_serv, 0,
		 N_("LVS Service")},

		POPT_AUTOHELP {0, 0, 0, 0, 0}
	};

	optCon = poptGetContext ("nanny", argc, argv, options, 0);

	poptReadDefaultConfig (optCon, 1);

	if ((rc = poptGetNextOpt (optCon)) < -1) {
		fprintf (stderr, _("nanny: bad argument %s: %s\n"),
			 poptBadOption (optCon, POPT_BADOPTION_NOALIAS),
			 poptStrerror (rc));
		return 1;
	}

	if (poptGetArg (optCon)) {
		fprintf (stderr, _("nanny: unexpected arguments\n"));
		return 1;
	}

	poptFreeContext (optCon);

	if (display_ver) {
		printf ("Program Version:\t%s\n", _PROGRAM_VERSION);
		printf ("Built:\t\t\t%s\n", DATE);	/* DATE pulled from Makefile */
		printf ("A component of:\t\tpiranha-%s-%s\n", VERSION, RELEASE);
		return 0;
	}

	if (server == (char *) NULL) {
		fprintf (stderr,
			 _("nanny: No address supplied. Use '--help' for help. \n"));
		return 1;
	}

	if (!inet_aton (server, &remoteAddr)) {
		fprintf (stderr, _("nanny: bad IP address -- %s\n"), server);
		return 1;
	}

	if (!fos_serv && !lvs_serv) {
		fprintf(stderr, _("nanny: unknown service type\n"));
		return 1;
	} else if (fos_serv) {
		service_type = SERV_FOS;
	} else if (lvs_serv) {
		service_type = SERV_LVS;
	}
	
	if (rport == -1) {
		rport = port;
	}
	
	if (reentryTime == 0) {
		if (service_type == SERV_LVS)
			reentryTime = 180;
		else
			reentryTime = interval;
	}

	/* Default reentry time depends on which nanny is going to run */
	logName ((char *) "nanny");

        if (useRegex)
                flags |= NANNY_FLAG_REGEX;

	if (noDaemon)
		flags |= LVS_FLAG_PRINTF | LVS_FLAG_SYSLOG;
	else
		flags |= NANNY_FLAG_ASDAEMON | LVS_FLAG_SYSLOG;

	if (noFork)
		flags |= LVS_FLAG_NOFORK;

	if (noRun | teststart)
		flags |= NANNY_FLAG_NORUN;

	if (verbose)
		flags |= NANNY_FLAG_VERBOSE;

	if (flags & NANNY_FLAG_ASDAEMON) {
		if (daemonize (flags | LVS_FLAG_NOPIDFILE))
			exit (0);
	}

	if (flags & LVS_FLAG_SYSLOG)
	  {
	    openlog ("nanny", LOG_PID, LOG_DAEMON);
	  }

	countThresh = reentryTime / interval;

	specifiedRM = routingMethod;
	if (*specifiedRM == '-')
		++specifiedRM;	/* Skip leading dash if there */

	switch (*specifiedRM) {
	case 'i':
		routingMethod = strdup ("-i");
		break;

	case 'g':
		routingMethod = strdup ("-g");
		break;

	case 'm':
	default:
		routingMethod = strdup ("-m");
		break;
	}

	/* send_program overrides send_str */

	if ((send_program != NULL) && (send_str != NULL)) {
		send_str = NULL;
		piranha_log (flags, (char *)
			     "External program use requested: (%s), IGNORING send string option (%s)\n",
			     send_program, send_str);
	}

	if ((port == 80) && (send_str == NULL) && (expect_str == NULL)
	    && (send_program == NULL)) {
	    	piranha_log (flags, (char *) "nanny: no monitor configured, assuming web service on port 80");
	    	send_str = (char*) http_send_str;
	    	expect_str = (char*) http_recv_str;
	}

	if (suppress == 0) {
		convert_str (send_str);
		convert_str (expect_str);
		/* Convert "\\x" characters into '\n' stuff */
	}

	if (service_type == SERV_FOS)
		piranha_log (flags, (char *)
			     "Failover service monitor for %s:%d started",
			     virtualAddress, port);
	else /* service_type == SERV_LVS */
		piranha_log (flags, (char *)
			     "starting LVS client monitor for %s:%d -> %s:%d",
			     virtualAddress, port, server, rport);
	
	InitCTX(flags);
	return run (flags, vsadmPath, virtualAddress, port, &remoteAddr, rport,
		    routingMethod, weight, interval, countThresh, scale,
		    loadCommand, send_program, send_str, expect_str,
		    quiesce_srv, service_type);
}
