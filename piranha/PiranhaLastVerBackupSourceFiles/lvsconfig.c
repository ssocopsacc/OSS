/*
** lvsconfig.c - config file parser
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
** 9/xx/1999	1.0	Erik Troan <ewt@redhat.com>
**		1.45	Mike Wangsmo <wanger@redhat.com>
**			Havoc Pennington <hp@redhat.com>
**			Initial release and repairs.
**
** 12/19/1999	1.46	Mike Wangsmo <wanger@redhat.com>
**		1.47	persistent parsing and initialization
**
** 12/19/1999	1.48	Phil "Bryce" Copeland <copeland@redhat.com>
**			changed typecasting and other 64bit stuff
**
** 2/3/2000	1.49	Keith Barrett <kbarrett@redhat.com>
**		1.51	Added comments and formatting.
**
** 2/18/2000	1.52	Keith Barrett <kbarrett@redhat.com>
**			Added persistent netmask
**
** 2/21/2000	1.53	Keith Barrett <kbarrett@redhat.com>
**			Initial send/expect fields in structure
**
** 2/26/2000	1.54	Keith Barrett <kbarrett@redhat.com>
**		1.58	Fixed protocol = xxx
**			Added failover service parsing
**			Added lvsRelocateFS() routine
**
** 3/3/2000	1.59	Keith Barrett <kbarrett@redhat.com>
**		1.60	Added lvsServiceType processing
**			Fixed memory violations with efence
**			Fixed error in parsing for fos
** 
** 8/4/2000	1.61	Phil "Bryce" Copeland <copeland@redhat.com>
**			Added 'debug_level =' directive to parser
**			Added 'nmask =' directive to parser
**			Added 'vip_nmask =' directive to parser
**
** 9/11/2000	1.62	Philip Copeland <copeland@redhat.com>
**			Fixed least connections to be lc not pcc
**			renamed LVS_SCHED_PCC to LVS_SCHED_LC
**
** 5/31/2001	1.63	Keith Barrett <kbarrett@redhat.com>
**			Don't report lines ending in "\r\n" as invalid
**			Fixed netmask logic (several places)
**			Missing require ip addresses will default to 0.0.0.0
**			(which will return an eventual error if used)
**			Removed ipchains element reference
**
** 6/14/2001	1.64	Philip Copeland <bryce@redhat.com>
**			fast fixup of /usr/sbin/ipvsadm to /sbin/ipvsadm
**			this is a speed fixup, it will be sorted out in
**			a define next week
**
** 7/2/2001     1.65    Tim Waugh <twaugh@redhat.com>
**                      Heartbeat on dedicated interface
**                      Shared SCSI
**
** 8/27/2001	1.66	Philip Copeland <bryce@redhat.com>
**			Merged in Wensongs fwmark patchs
**
** 22/9/2001	1.67	Philip Copeland <bryce@redhat.com>
**			Made lvsconfig aware of send_program option
**
** 16/10/2002           Mike McLean <mikem@redhat.com>
**                      Added use_regex boolean option to lvs config
**
*/

#define _GNU_SOURCE

#include <alloca.h>
#include <ctype.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "globals.h"
#include "lvsconfig.h"

#define LVS_SAW_PRIMARYSERVER	    (1UL << 0)
#define LVS_SAW_BACKUPSERVER	    (1UL << 1)
#define LVS_SAW_BACKUPMODE	    (1UL << 2)
#define LVS_SAW_USEHEARTBEAT	    (1UL << 3)
#define LVS_SAW_KEEPALIVETIME	    (1UL << 4)
#define LVS_SAW_DEADTIME	    (1UL << 5)
#define LVS_SAW_USEFILESYNC	    (1UL << 6)
#define LVS_SAW_RSHCOMMAND	    (1UL << 7)
#define LVS_SAW_VSADM		    (1UL << 8)
#define LVS_SAW_REDIRECTTYPE	    (1UL << 9)
#define LVS_SAW_HEARTBEATPORT	    (1UL << 10)
#define LVS_SAW_NATROUTER	    (1UL << 11)
#define LVS_SAW_NAT_NMASK	    (1UL << 12)
#define LVS_SAW_BACKUPACTIVE	    (1UL << 13)
#define LVS_SAW_VIRTUALSERVICE	    (1UL << 14)
#define LVS_SAW_FAILOVERSERVICE	    (1UL << 15)
#define LVS_SAW_SERVICETYPE	    (1UL << 16)
#define LVS_SAW_DEBUG_LEVEL	    (1UL << 17)
#define LVS_SAW_PRIMARYPRIVATE      (1UL << 18)
#define LVS_SAW_PRIMARYSHARED       (1UL << 19)
#define LVS_SAW_BACKUPPRIVATE       (1UL << 20)
#define LVS_SAW_BACKUPSHARED        (1UL << 21)
#define LVS_SAW_RCA		    (1UL << 22)
#define LVS_SAW_SERIAL_NO	    (1UL << 23)
#define LVS_SAW_USESYNCDAEMON	    (1UL << 24)
#define LVS_SAW_ACTIVE_CMD          (1UL << 25)
#define LVS_SAW_INACTIVE_CMD        (1UL << 26)
#define LVS_SAW_MONITORLINKS	    (1UL << 27)
#define LVS_SAW_HARDSHUTDOWN        (1UL << 28)
#define LVS_SAW_SYNCD_IFACE         (1UL << 29)
#define LVS_SAW_SYNCD_ID            (1UL << 30)
#define LVS_SAW_TCP_TIMEOUT         (1UL << 31)
#define LVS_SAW_TCPFIN_TIMEOUT      (1UL << 32)
#define LVS_SAW_UDP_TIMEOUT         (1UL << 33)

#define LVS_SAW_VS_CLIENTMONITOR    (1UL << 1)
#define LVS_SAW_VS_VIRTUALADDRESS   (1UL << 2)
#define LVS_SAW_VS_PROTOCOL	    (1UL << 3)
#define LVS_SAW_VS_SCHEDULER	    (1UL << 4)
#define LVS_SAW_VS_ISACTIVE	    (1UL << 5)
#define LVS_SAW_VS_PORT		    (1UL << 6)
#define LVS_SAW_VS_LOADMONITOR	    (1UL << 7)
#define LVS_SAW_VS_TIMEOUT	    (1UL << 8)
#define LVS_SAW_VS_REENTRYTIME	    (1UL << 9)
#define LVS_SAW_VS_MASTERSERVER	    (1UL << 10)
#define LVS_SAW_VS_DIRS		    (1UL << 11)
#define LVS_SAW_VS_PERSISTENT	    (1UL << 12)
#define LVS_SAW_VS_PMASK	    (1UL << 13)
#define LVS_SAW_VS_SEND_PROGRAM     (1UL << 14)
#define LVS_SAW_VS_SEND		    (1UL << 15)
#define LVS_SAW_VS_EXPECT	    (1UL << 16)
#define LVS_SAW_VS_FS_START	    (1UL << 17)
#define LVS_SAW_VS_FS_STOP	    (1UL << 18)
#define LVS_SAW_VS_VIP_NMASK	    (1UL << 19)
#define LVS_SAW_VS_FWMARK           (1UL << 20)
#define LVS_SAW_VS_QUIESCESERVER    (1UL << 21)
#define LVS_SAW_VS_USEREGEX         (1UL << 22)
#define LVS_SAW_VS_SORRYSERVER	    (1UL << 23)

#define LVS_SAW_AS_ADDRESS	    (1UL << 0)
#define LVS_SAW_AS_ISACTIVE	    (1UL << 1)
#define LVS_SAW_AS_PORT		    (1UL << 2)
#define LVS_SAW_AS_WEIGHT	    (1UL << 3)
#define LVS_SAW_AS_LOGFILE	    (1UL << 4)

#define LVS_MAX_TOKENS 100	/* Max tokens per line */

struct fileState
{
  char *contents;
  char *lineEnd;
  char *thisLine;
  int lineNum;
};

struct outputBuffer
{
  char *text;
  int len;
  int alloced;
  char *end;
  int block;			/* count of number of blocks */
};

struct tokenList
{
  char *preSpace;
  int preSpaceLen;
  char *argv[LVS_MAX_TOKENS];	/* The word elements on the line */
  char quoteType[LVS_MAX_TOKENS];	/*  "  or '  */
  char *ws[LVS_MAX_TOKENS];	/* white space between, and */
  /* after, argv members */
};

#define TOKEN(a) ((toks.argv[0] && a) && strcmp(toks.argv[0], a) == 0)

#define CHECK_EQUAL \
    if (toks.argv[1] ? strcmp(toks.argv[1], "=") : 1) \
	    return LVS_ERROR_EQUALEXPECTED;

#define CHECK_ARGS(count) \
    CHECK_EQUAL \
    if (!toks.argv[count + 1]) return LVS_ERROR_MISSINGARGS; \
    if (toks.argv[count + 2]) return LVS_ERROR_EXTRAARGS;

#define OUTPUT_STR(structName, field, tokNum, sawField) \
    saw |= sawField; \
    if (structName) \
	outputString(ob, &toks, tokNum, structName->field);

#define OUTPUT_NUM(structName, field, tokNum, sawField) \
    saw |= sawField; \
    if (structName) \
	outputNum(ob, &toks, tokNum, structName->field);

#define OUTPUT_IPADDR(structName, field, tokNum, sawField) \
    saw |= sawField; \
    if (structName) \
	outputIpAddr(ob, &toks, tokNum, structName->field);

#define OUTPUT_MISSING_STR(bittest, field, default, format) \
    if (!(saw & bittest) && (strcmp(field, default))) \
	outputFormat(ob, format, field);

#define OUTPUT_MISSING_NUM(bittest, field, default, format) \
    if (!(saw & bittest) && (field != default)) \
	outputFormat(ob, format, field);

#define OUTPUT_MISSING_IPADDR(bittest, field, format) \
    if (!(saw & bittest) && (*((int *) &field))) \
	outputFormat(ob, format, inet_ntoa(field));



void
freeTokens (struct tokenList *toks)
{
  int i;
  
  toks->preSpace = 0;
  toks->preSpaceLen = 0;
  for (i = 0; toks->argv[i]; i++)
    {
      free (toks->argv[i]);
      toks->argv[i] = 0;
      free (toks->ws[i]);
      toks->ws[i] = 0;
      toks->quoteType[i] = 0;
    }
}


/*
**  tokenizeString()
**
**  This function parses a string with the format "aaa = bbb" or
**  "aaa = 'bbb'" and copies the pieces and whitespace chunks into the
**  tokenList structure. Each element of argv[] is part of the line.
**
**  Passed:
**	*string		    Ptr to start of file buffer to convert
**	*tokens		    Ptr to tokenList structure to fill in
**
**  Returned:
**	tokenizeString()    Completion status
**
** Note: This routine assumes there is no white space before string!
*/

int
tokenizeString (char *string, struct tokenList *tokens)
{

  int i = 0;			/* Token index counter */
  char *current_ptr = string;
  char *end_ptr;

  while ((*current_ptr) && (i < (LVS_MAX_TOKENS - 1)))
    {

      end_ptr = current_ptr;
      while ((*end_ptr != 0) && (isblank (*end_ptr) == 0))
	end_ptr++;
      /* Make end_ptr equal to the last non-blank character in string */


      /*
         **  Test to see if we have encountered a quote. If so,
         **  we must be at the parameter value and need to
         **  remember what kind of quote character was used so we can find
         **  its partner.
       */
      switch (*current_ptr)
	{
	case '"':
	  tokens->quoteType[i] = '"';
	  current_ptr++;
	  break;

	case '\'':
	  tokens->quoteType[i] = '\'';
	  current_ptr++;
	  break;

	default:
	  tokens->quoteType[i] = '\0';
	}


      /*
         **  At this point, end_ptr either points to a null, \n, or whitespace.
         **  we may have already passed our end-quote if there were no
         **  spaces inside the quotes, so we have to investigate.
       */

      if (tokens->quoteType[i])
	{
	  while ((*end_ptr != 0) && (*end_ptr != '\n') &&
		 (*end_ptr != '\r') && (*end_ptr != tokens->quoteType[i]))
	    ++end_ptr;

	  if (*end_ptr == tokens->quoteType[i])
	    ++end_ptr;

	  if (end_ptr > current_ptr)
	    if (*(end_ptr - 1) != tokens->quoteType[i])
	      return LVS_ERROR_BADQUOTING;
	}

      tokens->argv[i] = malloc (end_ptr - current_ptr + 1);
      memcpy (tokens->argv[i], current_ptr, end_ptr - current_ptr);


      if (tokens->quoteType[i])
	tokens->argv[i][end_ptr - current_ptr - 1] = '\0';
      else
	tokens->argv[i][end_ptr - current_ptr] = '\0';


      if (!*end_ptr)
	{
	  tokens->ws[i] = strdup ("");
	}
      else
	{
	  current_ptr = end_ptr;

	  while ((*end_ptr != 0) && (isblank (*end_ptr) != 0))
	    end_ptr++;

	  tokens->ws[i] = malloc (end_ptr - current_ptr + 1);
	  memcpy (tokens->ws[i], current_ptr, end_ptr - current_ptr);
	  tokens->ws[i][end_ptr - current_ptr] = '\0';
	}

      i++;
      current_ptr = end_ptr;
    }

  tokens->argv[i] = NULL;
  return 0;
}




static void
appendToOutput (struct outputBuffer *ob, char *text, int len)
{

  if (!ob || ob->block)
    return;

  if (len)
    {
      if (ob->len + len >= ob->alloced)
	{
	  ob->alloced = ob->len + len + (len * 10);
	  ob->text = realloc (ob->text, ob->alloced);
	  ob->end = ob->text + ob->len;
	}

      memcpy (ob->end, text, len);

      ob->end += len;
      ob->len += len;
      *ob->end = '\0';
    }
}







static void
outputFormat (struct outputBuffer *ob, char *format, ...)
{

  char buf[1024];
  va_list args;

  va_start (args, format);
  vsprintf (buf, format, args);
  va_end (args);

  appendToOutput (ob, buf, strlen (buf));
}



#if defined(DEBUG)

static void
dumpToks (struct fileState *fs, struct tokenList *tokList, char *prefix)
{

  char **toks = tokList->argv;
  char **tok;

  printf ("%sline %d:", prefix, fs->lineNum);

  for (tok = toks; *tok; tok++)
    {
      printf ("|%s", *tok);
    }

  printf ("|\n");
}

#else

#define dumpToks(fs, toks, prefix)

#endif




int
getNextToks (struct fileState *fs, struct outputBuffer *ob,
	     struct tokenList *toks)
{

  char *current_ptr;
  char *wsStart;

  if (fs->lineEnd)
    wsStart = fs->lineEnd;
  else
    wsStart = fs->contents;


  while (1)
    {

      if (fs->lineEnd)
	current_ptr = fs->thisLine = fs->lineEnd + 1;
      else
	current_ptr = fs->thisLine = fs->contents;

      if (!*current_ptr)
	{
	  appendToOutput (ob, wsStart, current_ptr - wsStart);

	  *toks->argv = NULL;
	  toks->preSpace = NULL;
	  toks->preSpaceLen = 0;
	  return 0;
	}

      fs->lineEnd = strchr (fs->thisLine, '\r');
      if (fs->lineEnd == NULL)
	fs->lineEnd = strchr (fs->thisLine, '\n');
      fs->lineNum++;

      while (isblank (*current_ptr))
	current_ptr++;		/* Skip blank characters */

      if (*current_ptr == '#')
	current_ptr = fs->lineEnd;	/* skip to line end if comment */

      if ((*current_ptr != '\n') && (*current_ptr != '\r'))
	{
	  toks->preSpace = wsStart;
	  toks->preSpaceLen = current_ptr - wsStart;
	  *fs->lineEnd = '\0';

	  if (tokenizeString (current_ptr, toks))
	    return LVS_ERROR_BADQUOTING;

	  *fs->lineEnd = '\n';
	  return 0;
	}
    }

  /* abort(); */
  /* Unreachable! due to while(1) */
}



static int
getNum (int *ptr, char *tok)
{

  int i;
  char *end;

  i = strtol (tok, &end, 0);

  if (*end)
    return LVS_ERROR_INTEXPECTED;

  *ptr = i;
  return 0;
}



static int
getPort (int *ptr, char *tok)
{

  int i, rc;
  struct servent *service;

  rc = getNum (&i, tok);

  if (!rc)
    {
      *ptr = i;
      return 0;
    }

  service = getservbyname (tok, "tcp");

  if (!service)
    return LVS_ERROR_BADARGUMENT;

  *ptr = ntohs (service->s_port);
  return 0;
}



static int
getProtocol (int *ptr, char *tok)
{

  int rc = 0;

  if (ptr)
    {
      if (strcmp (tok, "tcp") == 0)
	*ptr = IPPROTO_TCP;
      else if (strcmp (tok, "udp") == 0)
	*ptr = IPPROTO_UDP;
      else
	rc = LVS_ERROR_BADARGUMENT;
    }
  else
    rc = LVS_ERROR_BADARGUMENT;

  return rc;
}



static int
getBoolean (int *ptr, char *tok)
{

  int i;
  int rc;

  if ((rc = getNum (&i, tok)))
    return rc;

  if (i == 0 || i == 1)
    *ptr = i;
  else
    return LVS_ERROR_BOOLEXPECTED;

  return 0;
}



static int
getList (char ***listPtr, char **tokList)
{

  char **list;
  int count;

  if (strcmp (tokList[0], "["))
    return LVS_ERROR_LISTEXPECTED;

  tokList++;

  for (count = 0; tokList[count] && strcmp (tokList[count], "]"); count++);

  if (!tokList[count])
    return LVS_ERROR_LISTEXPECTED;

  list = malloc (sizeof (*list) * (count + 1));

  for (count = 0; strcmp (tokList[count], "]"); count++)
    {
      list[count] = strdup (tokList[count]);
    }

  list[count] = NULL;
  *listPtr = list;
  return 0;
}
	

static int
getHostname (struct in_addr *addr, char **asName, char *tok)
{
  struct hostent *host;

  if (asName)
    *asName = strdup (tok);

  if (inet_aton (tok, addr))
    return 0;

  host = gethostbyname (tok);

  if (!host)
    return LVS_ERROR_BADARGUMENT;

  *addr = **((struct in_addr **) host->h_addr_list);
  return 0;
}



static void
outputString (struct outputBuffer *ob, struct tokenList *toks,
	      int updateField, char *newValue)
{

  int i;
  int j = 0;

  appendToOutput (ob, toks->preSpace, toks->preSpaceLen);

  if (newValue)
    j = strlen (newValue);

  for (i = 0; toks->argv[i]; i++)
    {
      if (i == updateField)
	{
	  appendToOutput (ob, newValue, j);
	}
      else
	appendToOutput (ob, toks->argv[i], strlen (toks->argv[i]));

      appendToOutput (ob, toks->ws[i], strlen (toks->ws[i]));
    }
}



static void
outputNum (struct outputBuffer *ob, struct tokenList *toks,
	   int updateField, int newValue)
{

  char val[50];

  sprintf (val, "%d", newValue);
  outputString (ob, toks, updateField, val);	/* return? in void?? */
}



static void
outputIpAddr (struct outputBuffer *ob, struct tokenList *toks,
	      int updateField, struct in_addr addr)
{

  outputString (ob, toks, updateField, inet_ntoa (addr));
}




static void
outputList (struct outputBuffer *ob, struct tokenList *toks,
	    int starters, char **list)
{

  int i;

  appendToOutput (ob, toks->preSpace, toks->preSpaceLen);

  /* The +1 here includes the opening [ and the white space after */

  for (i = 0; i < starters + 1; i++)
    {
      appendToOutput (ob, (char *) toks->argv[i], strlen (toks->argv[i]));
      appendToOutput (ob, (char *) toks->ws[i], strlen (toks->ws[i]));
    }


  /* We're left with "command = [ " already written. We could be more
     clever then we are here to try and get the spacing right, keep the
     order in the file, etc, but I doubt it's worth the trouble */

  for (i = 0; list[i]; i++)
    {
      appendToOutput (ob, (char *) list[i], strlen (list[i]));

      if (list[i + 1])
	appendToOutput (ob, (char *) " ", 1);
    }

  /* We could take the last token from the tokenList, but why bother? */
  appendToOutput (ob, (char *) " ]", 2);
}



static void
outputActualServer (struct outputBuffer *ob,
		    struct lvsService *eservice, unsigned long saw)
{

  if (!eservice)
    return;

OUTPUT_MISSING_IPADDR (LVS_SAW_AS_ADDRESS, eservice->address,
			 (char *) "\t\taddress = %s\n")
    OUTPUT_MISSING_NUM (LVS_SAW_AS_ISACTIVE, eservice->isActive,
			  -1, (char *) "\t\tactive = %d\n")
    OUTPUT_MISSING_NUM (LVS_SAW_AS_WEIGHT, eservice->weight,
			  1, (char *) "\t\tweight = %d\n")
    OUTPUT_MISSING_NUM (LVS_SAW_AS_PORT, eservice->port,
			  1, (char *) "\t\tport = %d\n")}



static int
parseActualServer (struct fileState *fs,
		   struct outputBuffer *ob,
		   struct lvsService *service, struct lvsService *eservice)
{

  struct tokenList toks;
  int rc;
  unsigned long saw = 0;

  rc = getNextToks (fs, ob, &toks);

  if (rc)
    return rc;

  while (*toks.argv && strcmp (toks.argv[0], "}"))
    {
      dumpToks (fs, &toks, "		    actual server: ");

      if (TOKEN ("address"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getHostname (&service->address, NULL, toks.argv[2])))
	    return rc;
	  OUTPUT_IPADDR (eservice, address, 2, LVS_SAW_AS_ADDRESS);

	}
      else if (TOKEN ("active"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getBoolean (&service->isActive, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eservice, isActive, 2, LVS_SAW_AS_ISACTIVE);

	}
      else if (TOKEN ("weight"))
	{
	  CHECK_ARGS (1) if ((rc = getNum (&service->weight, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eservice, weight, 2, LVS_SAW_AS_WEIGHT);

	}
      else if (TOKEN ("port"))
	{
	  CHECK_ARGS (1) if ((rc = getNum (&service->port, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eservice, port, 2, LVS_SAW_AS_PORT);

	}
      else
	return LVS_ERROR_BADCOMMAND;

      freeTokens (&toks);
      rc = getNextToks (fs, ob, &toks);
      if (rc)
	return rc;
    }

  freeTokens (&toks);

  if (eservice)
    {
      char *lastNewline;

      lastNewline = toks.preSpace + toks.preSpaceLen - 1;

      while (lastNewline > toks.preSpace && *lastNewline != '\n')
	lastNewline--;

      if (*lastNewline == '\n')
	lastNewline++;

      appendToOutput (ob, toks.preSpace, lastNewline - toks.preSpace);
      toks.preSpaceLen -= lastNewline - toks.preSpace;
      toks.preSpace = lastNewline;
      outputActualServer (ob, eservice, saw);
    }

  outputString (ob, &toks, -1, NULL);

  if (!toks.argv)
    return LVS_ERROR_EOF;
  else if (toks.argv[1])
    return LVS_ERROR_EXTRAARGS;

  return 0;
}



static void
outputVirtualServer (struct outputBuffer *ob,
		     struct lvsVirtualServer *eserver,
		     unsigned long saw, int outputRealServers)
{
  int i;


  if (!eserver)
    return;

  OUTPUT_MISSING_STR (LVS_SAW_VS_CLIENTMONITOR, eserver->clientMonitor,
		      (char *) "/usr/sbin/nanny",
		      (char *) "\tclient_monitor = %s\n")
    if (!(saw & LVS_SAW_VS_VIRTUALADDRESS))
    outputFormat (ob, (char *) "\taddress = %s %s\n",
		  inet_ntoa (eserver->virtualAddress),
		  eserver->virtualDevice);

  OUTPUT_MISSING_NUM (LVS_SAW_VS_ISACTIVE, eserver->isActive,
		      -1, (char *) "\tactive = %d\n") if (eserver->persistent)
    {
      OUTPUT_MISSING_NUM (LVS_SAW_VS_PERSISTENT, eserver->persistent,
			  0, (char *) "\tpersistent = %d\n")
	if (eserver->pmask.s_addr)
	if (!(saw & LVS_SAW_VS_PMASK))
	  outputFormat (ob, (char *) "\tpmask = %s\n",
			inet_ntoa (eserver->pmask));
    }

  if (!(saw & LVS_SAW_VS_PROTOCOL) && eserver->protocol != IPPROTO_TCP)
    outputFormat (ob, (char *) "\tprotocol = udp\n");

  if (!(saw & LVS_SAW_VS_SCHEDULER) && eserver->scheduler != LVS_SCHED_WLC)
    {
      if (eserver->scheduler == LVS_SCHED_LC)
	outputFormat (ob, (char *) "\tscheduler = lc\n");
      else if (eserver->scheduler == LVS_SCHED_RR)
	outputFormat (ob, (char *) "\tscheduler = rr\n");
      else if (eserver->scheduler == LVS_SCHED_WRR)
	outputFormat (ob, (char *) "\tscheduler = wrr\n");
      else if (eserver->scheduler == LVS_SCHED_LBLC)
	outputFormat (ob, (char *) "\tscheduler = lblc\n");
      else if (eserver->scheduler == LVS_SCHED_LBLCR)
	outputFormat (ob, (char *) "\tscheduler = lblcr\n");
      else if (eserver->scheduler == LVS_SCHED_DH)
	outputFormat (ob, (char *) "\tscheduler = dh\n");
      else if (eserver->scheduler == LVS_SCHED_SH)
	outputFormat (ob, (char *) "\tscheduler = sh\n");
    }

  OUTPUT_MISSING_NUM (LVS_SAW_VS_PORT, eserver->port,
		      80, (char *) "\tport = %d\n")
/*
**    if (eserver->send_str) {
**	  sprintf(tmp_buf, "%c%s%c",'"', eserver->send_str, '"');
**	  outputFormat(ob, "\tsend = %s\n", tmp_buf);
**    }
**
**    if (eserver->expect_str) {
**	  sprintf(tmp_buf, "%c%s%c",'"', eserver->expect_str, '"');
**	  outputFormat(ob, "\texpect = %s\n", tmp_buf);
**    }
*/
    if (eserver->send_str && *eserver->send_str)
    	OUTPUT_MISSING_STR (LVS_SAW_VS_SEND, eserver->send_str,
		(char *) "", (char *) "\tsend = %s\n")
    if (eserver->send_program && *eserver->send_program)
    	OUTPUT_MISSING_STR (LVS_SAW_VS_SEND_PROGRAM, eserver->send_program,
		(char *) "", (char *) "\tsend_program = %s\n")
    if (eserver->expect_str && *eserver->expect_str)
    	OUTPUT_MISSING_STR (LVS_SAW_VS_EXPECT, eserver->expect_str,
		(char *) "", (char *) "\texpect = %s\n")
    if (eserver->start_cmd)
	OUTPUT_MISSING_STR (LVS_SAW_VS_FS_START, eserver->start_cmd,
		(char *) "", (char *) "\tstart_cmd = %s\n")
    if (eserver->stop_cmd)
    	OUTPUT_MISSING_STR (LVS_SAW_VS_FS_STOP, eserver->stop_cmd,
		(char *) "", (char *) "\tstop_cmd = %s\n")
    if (eserver->loadMonitor)
	OUTPUT_MISSING_STR (LVS_SAW_VS_LOADMONITOR, eserver->loadMonitor,
		(char *) "", (char *) "\tload_monitor = %s\n")
	OUTPUT_MISSING_NUM (LVS_SAW_VS_TIMEOUT, eserver->timeout,
		10, (char *) "\ttimeout = %d\n")
	OUTPUT_MISSING_NUM (LVS_SAW_VS_REENTRYTIME,
		eserver->reentryTime, 180,
		(char *) "\treentry = %d\n")
	OUTPUT_MISSING_IPADDR (LVS_SAW_VS_MASTERSERVER, eserver->masterServer,
				     (char *) "\tmaster = %s\n")

    if (outputRealServers) {
	i = -1;
	while (++i < eserver->numServers)
		{
			outputFormat (ob, (char *) "\n\tserver %s {\n",
				eserver->servers[i].name);
				outputActualServer (ob, eserver->servers + i, 0);
			outputFormat (ob, (char *) "\t}\n");
		}
	}
}



/*
**  parseVirtualServer()
**
**  This routine parses the virtual server section of a memory buffer
**  containing the entire contents of an lvs configuration file.
**
**  Passed:
**	*fs
**	*ob
**	*vserver
**	*eserver
**
**  Returned:
**	parseVirtualServer()	Completion status
*/

static int
parseVirtualServer (struct fileState *fs,
		    struct outputBuffer *ob,
		    struct lvsVirtualServer *vserver,
		    struct lvsVirtualServer *eserver)
{

  struct tokenList toks;
  unsigned int rc;
  int i, j;
  unsigned long saw = 0;
  char *sectionMarkers = NULL;

  if (eserver)
    if (eserver->numServers)
      sectionMarkers = alloca (eserver->numServers * sizeof (*sectionMarkers));

  rc = getNextToks (fs, ob, &toks);
  if (rc)
    return rc;

  /* Zap the sorry server... */
  memset(&vserver->sorry_server, 0, sizeof(vserver->sorry_server));

  while (*toks.argv && strcmp (toks.argv[0], "}"))
    {
      dumpToks (fs, &toks, "	virtual server: ");

      if (TOKEN ("active"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getBoolean (&vserver->isActive, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, isActive, 2, LVS_SAW_VS_ISACTIVE);
	}
      else if (TOKEN ("address"))
	{
	  CHECK_ARGS (2);
		
	  if ((rc = getHostname (&vserver->virtualAddress, NULL,
				   toks.argv[2])))
	    return rc;

	  vserver->virtualDevice = strdup (toks.argv[3]);
	  /*XXX virtual device isn't getting written */

	  saw |= LVS_SAW_VS_VIRTUALADDRESS;
	  if (eserver)
	    {
	      appendToOutput (ob, toks.preSpace, toks.preSpaceLen);
	      /* "address<ws>=<ws><ip><ws><dev><ws>" */
	      outputFormat (ob, (char *) "%s%s%s%s%s%s%s%s",
			    toks.argv[0], toks.ws[0], toks.argv[1],
			    toks.ws[1], inet_ntoa (vserver->virtualAddress),
			    toks.ws[2], vserver->virtualDevice, toks.ws[3]);
	    }

	}
      else if (TOKEN ("sorry_server"))
	{
	  CHECK_ARGS (1) if (inet_aton (toks.argv[2], &vserver->sorry_server))
	    {
	      OUTPUT_IPADDR (eserver, sorry_server, 2, LVS_SAW_VS_SORRYSERVER);
	    }
	  else
	    return LVS_ERROR_BADHOSTNAME;

	}
      else if (TOKEN ("vip_nmask"))
	{
	  CHECK_ARGS (1) if (inet_aton (toks.argv[2], &vserver->vip_nmask))
	    {
	      OUTPUT_IPADDR (eserver, vip_nmask, 2, LVS_SAW_VS_VIP_NMASK);
	    }
	  else
	    return LVS_ERROR_BADNETMASK;

	}
      else if (TOKEN ("fwmark"))
	{
	  CHECK_ARGS (1) if ((rc = getNum ((int *)&vserver->fwmark, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, fwmark, 2, LVS_SAW_VS_FWMARK);
	}
      else if (TOKEN ("protocol"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getProtocol (&vserver->protocol, toks.argv[2])))
	    return rc;

	  if (eserver)
	    {
	      switch (eserver->protocol)
		{
		case IPPROTO_TCP:
		  outputString (ob, &toks, 2, (char *) "tcp");
		  break;
		case IPPROTO_UDP:
		  outputString (ob, &toks, 2, (char *) "udp");
		  break;
		}
	    }

	  saw |= LVS_SAW_VS_PROTOCOL;

	}
      else if (TOKEN ("port"))
	{
	  CHECK_ARGS (1) if ((rc = getPort (&vserver->port, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, port, 2, LVS_SAW_VS_PORT);

	}
      else if (TOKEN ("scheduler"))
	{
	  CHECK_ARGS (1) if (!strcmp (toks.argv[2], "lc"))
	    vserver->scheduler = LVS_SCHED_LC;
	  else if (!strcmp (toks.argv[2], "rr"))
	    vserver->scheduler = LVS_SCHED_RR;
	  else if (!strcmp (toks.argv[2], "wlc"))
	    vserver->scheduler = LVS_SCHED_WLC;
	  else if (!strcmp (toks.argv[2], "wrr"))
	    vserver->scheduler = LVS_SCHED_WRR;
	  else if (!strcmp (toks.argv[2], "lblc"))
	    vserver->scheduler = LVS_SCHED_LBLC;
	  else if (!strcmp (toks.argv[2], "lblcr"))
	    vserver->scheduler = LVS_SCHED_LBLCR;
	  else if (!strcmp (toks.argv[2], "dh"))
	    vserver->scheduler = LVS_SCHED_DH;
	  else if (!strcmp (toks.argv[2], "sh"))
	    vserver->scheduler = LVS_SCHED_SH;
	  else
	    return LVS_ERROR_BADARGUMENT;

	  if (eserver)
	    {
	      switch (eserver->scheduler)
		{

		case LVS_SCHED_LC:
		  outputString (ob, &toks, 2, (char *) "lc");
		  break;

		case LVS_SCHED_RR:
		  outputString (ob, &toks, 2, (char *) "rr");
		  break;

		case LVS_SCHED_WLC:
		  outputString (ob, &toks, 2, (char *) "wlc");
		  break;

		case LVS_SCHED_LBLC:
		  outputString (ob, &toks, 2, (char *) "lblc");
		  break;

		case LVS_SCHED_LBLCR:
		  outputString (ob, &toks, 2, (char *) "lblcr");
		  break;

		case LVS_SCHED_DH:
		  outputString (ob, &toks, 2, (char *) "dh");
		  break;

		case LVS_SCHED_SH:
		  outputString (ob, &toks, 2, (char *) "sh");
		  break;

		case LVS_SCHED_UNKNOWN:	/* if we don't know make it wrr */
		case LVS_SCHED_WRR:
		  outputString (ob, &toks, 2, (char *) "wrr");
		  break;
		}
	    }

	  saw |= LVS_SAW_VS_SCHEDULER;

	}
      else if (TOKEN ("persistent"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getNum (&vserver->persistent, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, persistent, 2, LVS_SAW_VS_PERSISTENT);
	}
      else if (TOKEN ("pmask"))
	{
	  CHECK_ARGS (1) if (inet_aton (toks.argv[2], &vserver->pmask))
	    saw |= LVS_SAW_VS_PMASK;

	  if (!strcmp (toks.argv[2], "255.255.255.255"))
	    (void) inet_aton ("0.0.0.0", &vserver->pmask);
	  /* 255.255.255.255 not allowed */

	  if (eserver)
	    {
	      if (vserver->pmask.s_addr)
		{
		  appendToOutput (ob, toks.preSpace, toks.preSpaceLen);
		  /* "pmask<ws>=<ws><ip><ws>" */
		  outputFormat (ob, (char *) "\t%s%s%s%s%s%s",
				toks.argv[0], toks.ws[0], toks.argv[1],
				toks.ws[1], inet_ntoa (vserver->pmask),
				toks.ws[2]);
		}
	    }

	}
      else if (TOKEN ("client_monitor"))
	{
	  CHECK_ARGS (1) free (vserver->clientMonitor);
	  vserver->clientMonitor = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, clientMonitor, 2, LVS_SAW_VS_CLIENTMONITOR);

	}
      else if (TOKEN ("send_program"))
	{
	  CHECK_ARGS (1) free (vserver->send_program);
	  if (toks.quoteType[2])
	    {
	      vserver->send_program = malloc (strlen (toks.argv[2]) + 3);
	      (void) sprintf (vserver->send_program, "%c%s%c",
			      toks.quoteType[2], toks.argv[2],
			      toks.quoteType[2]);
	    }
	  else
	    vserver->send_program = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, send_program, 2, LVS_SAW_VS_SEND_PROGRAM);

	}
      else if (TOKEN ("send"))
	{
	  CHECK_ARGS (1) free (vserver->send_str);
	  if (toks.quoteType[2])
	    {
	      vserver->send_str = malloc (strlen (toks.argv[2]) + 3);
	      (void) sprintf (vserver->send_str, "%c%s%c",
			      toks.quoteType[2], toks.argv[2],
			      toks.quoteType[2]);
	    }
	  else
	    vserver->send_str = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, send_str, 2, LVS_SAW_VS_SEND);

	}
      else if (TOKEN ("expect"))
	{
	  CHECK_ARGS (1) free (vserver->expect_str);
	  if (toks.quoteType[2])
	    {
	      vserver->expect_str = malloc (strlen (toks.argv[2]) + 3);
	      (void) sprintf (vserver->expect_str, "%c%s%c",
			      toks.quoteType[2], toks.argv[2],
			      toks.quoteType[2]);
	    }
	  else
	    vserver->expect_str = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, expect_str, 2, LVS_SAW_VS_EXPECT);

	}
      else if (TOKEN ("use_regex"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getBoolean (&vserver->useRegex, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, useRegex, 2, LVS_SAW_VS_USEREGEX);
	}
      else if (TOKEN ("timeout"))
	{
	  CHECK_ARGS (1) if ((rc = getNum (&vserver->timeout, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, timeout, 2, LVS_SAW_VS_TIMEOUT);

	}
      else if (TOKEN ("reentry"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getNum (&vserver->reentryTime, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, reentryTime, 2, LVS_SAW_VS_REENTRYTIME);

	}
      else if (TOKEN ("load_monitor"))
	{
	  CHECK_ARGS (1) free (vserver->loadMonitor);
	  vserver->loadMonitor = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, loadMonitor, 2, LVS_SAW_VS_LOADMONITOR);
	}
      else if (TOKEN ("quiesce_server"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getBoolean (&vserver->quiesceServer, toks.argv[2])))
	    return rc;
	  OUTPUT_NUM (eserver, quiesceServer, 2, LVS_SAW_VS_QUIESCESERVER);
	}
      else if (TOKEN ("start_cmd"))
	{			/* Only on failover service */
	  CHECK_ARGS (1) free (vserver->start_cmd);
	  if (toks.quoteType[2])
	    {
	      vserver->start_cmd = malloc (strlen (toks.argv[2]) + 3);
	      (void) sprintf (vserver->start_cmd, "%c%s%c",
			      toks.quoteType[2], toks.argv[2],
			      toks.quoteType[2]);
	    }
	  else
	    vserver->start_cmd = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, start_cmd, 2, LVS_SAW_VS_FS_START);

	}
      else if (TOKEN ("stop_cmd"))
	{			/* Only on failover service */
	  CHECK_ARGS (1) free (vserver->stop_cmd);
	  if (toks.quoteType[2])
	    {
	      vserver->stop_cmd = malloc (strlen (toks.argv[2]) + 3);
	      (void) sprintf (vserver->stop_cmd, "%c%s%c",
			      toks.quoteType[2], toks.argv[2],
			      toks.quoteType[2]);
	    }
	  else
	    vserver->stop_cmd = strdup (toks.argv[2]);
	  OUTPUT_STR (eserver, stop_cmd, 2, LVS_SAW_VS_FS_STOP);

	}
      else if (TOKEN ("master"))
	{
	  CHECK_ARGS (1)
	    if ((rc =
		 getHostname (&vserver->masterServer, NULL, toks.argv[2])))
	    return rc;
	  OUTPUT_IPADDR (eserver, masterServer, 2, LVS_SAW_VS_MASTERSERVER);

	}
      else if (TOKEN ("dirs"))
	{
	  CHECK_EQUAL if ((rc = getList (&vserver->dirs, toks.argv + 2)))
	    return rc;
	  if (eserver)
	    outputList (ob, &toks, 2, eserver->dirs);

	  saw |= LVS_SAW_VS_DIRS;

	}
      else if (TOKEN ("server"))
	{
	  if (!toks.argv[1] || !toks.argv[2])
	    return LVS_ERROR_MISSINGARGS;
	  if (toks.argv[3])
	    return LVS_ERROR_EXTRAARGS;
	  if (strcmp (toks.argv[2], "{"))
	    return LVS_ERROR_MISSINGARGS;

	  i = vserver->numServers++;
	  vserver->servers = realloc (vserver->servers,
				      sizeof (*vserver->servers) *
				      vserver->numServers);
	  memset (vserver->servers + i, 0, sizeof (*vserver->servers));

	  vserver->servers[i].name = strdup (toks.argv[1]);
	  vserver->servers[i].port = vserver->port;
	  vserver->servers[i].weight = 1;

	  if (eserver)
	    {
	      for (j = 0; j < eserver->numServers; j++)
		if (!strcmp (eserver->servers[j].name,
			     vserver->servers[i].name))
		  break;
	      if (j == eserver->numServers)
		j = -1;
	      else
		{
		  outputString (ob, &toks, 1, eserver->servers[j].name);
		  if (sectionMarkers)
		    sectionMarkers[j] = 1;
		}
	    }
	  else
	    {
	      j = -1;
	    }

	  rc = parseActualServer (fs, ob, vserver->servers + i,
				  j == -1 ? NULL : eserver->servers + j);

	  if (rc)
	    return rc;
	}
      else
	return LVS_ERROR_BADCOMMAND;

      freeTokens (&toks);
      getNextToks (fs, ob, &toks);
      if (rc)
	return rc;
    }

  freeTokens (&toks);

  /*
  **       End of testing for virtual server tokens
  */

  if (eserver)
    {
      /*
         **  First; write any outstanding lines up to the end of this
         **  virtual server (except for the closing brace).
       */
      appendToOutput (ob, toks.preSpace, toks.preSpaceLen);


      /*  Old logic:
         **  toks.preSpace++;
         **  toks.preSpaceLen--;
         **  Skip the \n, next char is {
       */

      /* New logic: */
      toks.preSpace += toks.preSpaceLen;
      toks.preSpaceLen = 0;
      /* Alternative is to search for the { */

      outputVirtualServer (ob, eserver, saw, 0);
      /* Output any missing required parameters */


      i = -1;
      while (++i < eserver->numServers)
	{
	  if (!sectionMarkers[i])
	    {
	      outputFormat (ob, (char *) "\n\tserver %s {\n",
			    eserver->servers[i].name);
	      outputActualServer (ob, eserver->servers + i, 0);
	      outputFormat (ob, (char *) "\t}\n");
	    }
	}
    }

  outputString (ob, &toks, -1, NULL);
  /* Write out closing { and whatever else */


  if (!toks.argv)
    return LVS_ERROR_EOF;
  else if (toks.argv[1])
    return LVS_ERROR_EXTRAARGS;

  return 0;
}




/*
** parseConfiguration() -- Main parsing routine.
**
** Passed:
**     *fs	 Ptr to fileState struct containing the config file contents
**     *ob	 [Optional] Ptr to output buffer. Can be NULL if unused.
**     *config	 Ptr to lvsConfig structure to fill in.
**     *eConfig	 [Optional] Ptr to lvsConfig structure. Can be NULL if unused.
**		 This parameter is for merging config files (this happens
**		 when lvsconfig+main is externally called by a GUI).
**
** Returned:
**     *config		     structure elements updated.
**     parseConfiguration()  Completion status.
*/

static int
parseConfiguration (struct fileState *fs,
		    struct outputBuffer *ob,
		    struct lvsConfig *config, struct lvsConfig *eConfig)
{

  struct tokenList toks;
  int rc, i, j;
  char *sectionMarkers = NULL;
  char *current_ptr;
  unsigned long saw = 0;

  if (eConfig)
    sectionMarkers = alloca (eConfig->numVirtServers *
			     sizeof (*sectionMarkers));

  rc = getNextToks (fs, ob, &toks);
  if (rc)
    return rc;

  while (*toks.argv)
    {
      dumpToks (fs, &toks, "");	/* for debugging */

      if (TOKEN ("primary"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getHostname (&config->primaryServer,
				   &config->primaryServerName, toks.argv[2])))
	    return rc;
	  if (config->primaryServer.s_addr)
	    {
	    OUTPUT_STR (eConfig, primaryServerName, 2,
			  LVS_SAW_PRIMARYSERVER)}
	  else
	    return LVS_ERROR_BADHOSTNAME;

	}
      else if (TOKEN ("serial_no"))
	{
	  CHECK_ARGS (1) if ((rc = getNum (&config->serial_no, toks.argv[2])))
	    return rc;
	OUTPUT_NUM (eConfig, serial_no, 2, LVS_SAW_SERIAL_NO)}
      else if (TOKEN ("primary_private"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getHostname (&config->primaryPrivate,
				   &config->primaryPrivateName,
				   toks.argv[2])))
	    return rc;
	  if (config->primaryPrivate.s_addr)
	    {
	    OUTPUT_STR (eConfig, primaryPrivateName, 2,
			  LVS_SAW_PRIMARYPRIVATE)}
	  else
	    return LVS_ERROR_BADHOSTNAME;

	}
      else if (TOKEN ("primary_shared"))
	{
	  CHECK_ARGS (1) free (config->primaryShared);
	  config->primaryShared = strdup (toks.argv[2]);
	OUTPUT_STR (eConfig, primaryShared, 2, LVS_SAW_PRIMARYSHARED)}
      else if (TOKEN ("backup"))
	{
	  CHECK_ARGS (1)
	    if ((rc = getHostname (&config->backupServer,
				   &config->backupServerName, toks.argv[2])))
	    return rc;
	  if (eConfig && eConfig->backupServerName)
	    OUTPUT_STR (eConfig, backupServerName, 2, LVS_SAW_BACKUPSERVER)}
	    else
	  if (TOKEN ("backup_active"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getBoolean (&config->backupActive, toks.argv[2])))
		return rc;
	      OUTPUT_NUM (eConfig, backupActive, 2, LVS_SAW_BACKUPACTIVE);

	    }
	  else if (TOKEN ("backup_private"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getHostname (&config->backupPrivate,
				       &config->backupPrivateName,
				       toks.argv[2])))
		return rc;
	      if (config->backupPrivate.s_addr)
		{
		OUTPUT_STR (eConfig, backupPrivateName, 2,
			      LVS_SAW_BACKUPPRIVATE)}
	      else
		return LVS_ERROR_BADHOSTNAME;

	    }
	  else if (TOKEN ("backup_shared"))
	    {
	      CHECK_ARGS (1) free (config->backupShared);
	      config->backupShared = strdup (toks.argv[2]);
	    OUTPUT_STR (eConfig, backupShared, 2, LVS_SAW_BACKUPSHARED)}
	  else if (TOKEN ("reservation_conflict_action"))
	    {
	      CHECK_ARGS (1)
		if (strcmp (toks.argv[2], "nothing") &&
		    strcmp (toks.argv[2], "preempt"))
		return LVS_ERROR_BADARGUMENT;
	      free (config->reservation_conflict_action);
	      config->reservation_conflict_action = strdup (toks.argv[2]);
	    OUTPUT_STR (eConfig, backupShared, 2, LVS_SAW_RCA)}
	  else if (TOKEN ("nat_nmask"))
	    {
	      CHECK_ARGS (1) if (inet_aton (toks.argv[2], &config->nat_nmask))
		{
		  OUTPUT_IPADDR (eConfig, nat_nmask, 2, LVS_SAW_NAT_NMASK);
		}
	      else
		return LVS_ERROR_BADNETMASK;

	    }
	  else if (TOKEN ("nat_router"))
	    {
	      CHECK_ARGS (2)
		if ((rc =
		     getHostname (&config->natRouter, NULL, toks.argv[2])))
		return rc;
	      config->natRouterDevice = strdup (toks.argv[3]);

	      saw |= LVS_SAW_NATROUTER;

	      if (eConfig)
		{
		  appendToOutput (ob, toks.preSpace, toks.preSpaceLen);
		  outputFormat (ob, (char *) "%s%s%s%s%s%s%s%s",
				toks.argv[0], toks.ws[0], toks.argv[1],
				toks.ws[1], inet_ntoa (eConfig->natRouter),
				toks.ws[2], eConfig->natRouterDevice,
				toks.ws[3]);
		}

	    }
          else if (TOKEN ("active_cmd"))
            {
              CHECK_ARGS (1) free (config->activeCommand);
                config->activeCommand = strdup (toks.argv[2]);
              OUTPUT_STR (eConfig, activeCommand, 2, LVS_SAW_ACTIVE_CMD);
            }
          else if (TOKEN ("inactive_cmd"))
            {
              CHECK_ARGS (1) free (config->inactiveCommand);
                config->inactiveCommand = strdup (toks.argv[2]);
              OUTPUT_STR (eConfig, inactiveCommand, 2, LVS_SAW_ACTIVE_CMD);
            }
	  else if (TOKEN ("monitor_links"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum(&config->monitorLinks, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, monitorLinks, 2, LVS_SAW_MONITORLINKS)}
	  else if (TOKEN ("debug_level"))
	    {
	      CHECK_ARGS (1) free (config->debug_level);
	      config->debug_level = strdup (toks.argv[2]);

	    OUTPUT_STR (eConfig, debug_level, 2, LVS_SAW_DEBUG_LEVEL)}
          else if (TOKEN ("hard_shutdown"))
            {
              CHECK_ARGS (1)
                if ((rc = getBoolean (&config->hardShutdown, toks.argv[2])))
                return rc;
            OUTPUT_NUM (eConfig, hardShutdown, 2, LVS_SAW_HARDSHUTDOWN)}
	  else if (TOKEN ("ipvsadm"))
	    {
	      CHECK_ARGS (1) free (config->vsadm);
	      config->vsadm = strdup (toks.argv[2]);
	    OUTPUT_STR (eConfig, vsadm, 2, LVS_SAW_VSADM)}
	  else if (TOKEN ("keepalive"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->keepAliveTime, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, keepAliveTime, 2, LVS_SAW_KEEPALIVETIME)}
	  else if (TOKEN ("deadtime"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->deadTime, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, deadTime, 2, LVS_SAW_DEADTIME)}
	  else if (TOKEN ("rsh_command"))
	    {
	      CHECK_ARGS (1) free (config->rshCommand);
	      config->rshCommand = strdup (toks.argv[2]);
	    OUTPUT_STR (eConfig, rshCommand, 2, LVS_SAW_RSHCOMMAND)}
	  else if (TOKEN ("syncdaemon"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getBoolean (&config->useSyncDaemon, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, useSyncDaemon, 2, LVS_SAW_USESYNCDAEMON)}
	  else if (TOKEN ("syncd_iface"))
	    {
	      CHECK_ARGS (1) free (config->syncdInterface);
	      config->syncdInterface = strdup (toks.argv[2]);
	    OUTPUT_STR (eConfig, syncdInterface, 2, LVS_SAW_SYNCD_IFACE)}
	  else if (TOKEN ("syncd_id"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->syncdID, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, syncdID, 2, LVS_SAW_SYNCD_ID)}
	  else if (TOKEN ("tcp_timeout"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->tcpTimeout, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, tcpTimeout, 2, LVS_SAW_TCP_TIMEOUT)}
	  else if (TOKEN ("tcpfin_timeout"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->tcpfinTimeout, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, tcpfinTimeout, 2, LVS_SAW_TCPFIN_TIMEOUT)}
	  else if (TOKEN ("udp_timeout"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getNum (&config->udpTimeout, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, udpTimeout, 2, LVS_SAW_UDP_TIMEOUT)}
	  else if (TOKEN ("heartbeat"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getBoolean (&config->useHeartbeat, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, useHeartbeat, 2, LVS_SAW_USEHEARTBEAT)}
	  else if (TOKEN ("heartbeat_port"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getPort (&config->heartbeatPort, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, heartbeatPort, 2, LVS_SAW_HEARTBEATPORT)}
	  else if (TOKEN ("sync"))
	    {
	      CHECK_ARGS (1)
		if ((rc = getBoolean (&config->useFileSync, toks.argv[2])))
		return rc;
	    OUTPUT_NUM (eConfig, useFileSync, 2, LVS_SAW_USEFILESYNC)}
	  else if (TOKEN ("network"))
	    {
	      CHECK_ARGS (1) if (!strcmp (toks.argv[2], "direct"))
		config->redirectType = LVS_REDIRECT_DIRECT;
	      else if (!strcmp (toks.argv[2], "nat"))
		config->redirectType = LVS_REDIRECT_NAT;
	      else if (!strcmp (toks.argv[2], "tunnel"))
		config->redirectType = LVS_REDIRECT_TUNNEL;
	      else
		return LVS_ERROR_BADARGUMENT;

	      if (eConfig)
		{
		  switch (eConfig->redirectType)
		    {

		    case LVS_REDIRECT_UNKNOWN:
		    case LVS_REDIRECT_DIRECT:
		      outputString (ob, &toks, 2, (char *) "direct");
		      break;

		    case LVS_REDIRECT_NAT:
		      outputString (ob, &toks, 2, (char *) "nat");
		      break;

		    case LVS_REDIRECT_TUNNEL:
		      outputString (ob, &toks, 2, (char *) "tunnel");
		      break;
		    }
		}
	      saw |= LVS_SAW_REDIRECTTYPE;


	    }
	  else if (TOKEN ("service"))
	    {
	      CHECK_ARGS (1) if (!strcmp (toks.argv[2], "lvs"))
		config->lvsServiceType = LVS_SERVICE_TYPE_LVS;
	      else if (!strcmp (toks.argv[2], "fos"))
		config->lvsServiceType = LVS_SERVICE_TYPE_FOS;
	      else
		return LVS_ERROR_BADARGUMENT;

	      if (eConfig)
		{
		  switch (eConfig->lvsServiceType)
		    {

		    case LVS_SERVICE_TYPE_FOS:
		      outputString (ob, &toks, 2, (char *) "fos");
		      break;

		    default:
		      outputString (ob, &toks, 2, (char *) "lvs");
		      break;
		    }
		}
	      saw |= LVS_SAW_SERVICETYPE;


	    }
	  else if ((TOKEN ("virtual")) || (TOKEN ("failover")))
	    {
	      /* We are about to enter the virtual server section */

	      /*
	         ** Note that Failover Services are identical structures,
	         ** so they both use the Virtual Server structure list.
	         ** The only difference is that a flag is set indicating
	         ** that this is a failover service instead if a virtual
	         ** service. Other program must skip these if appropriate.
	       */

	      if (!toks.argv[1] || !toks.argv[2])
		return LVS_ERROR_MISSINGARGS;

	      if (toks.argv[3])
		return LVS_ERROR_EXTRAARGS;

	      if (strcmp (toks.argv[2], "{"))
		return LVS_ERROR_MISSINGARGS;



	      /* if (TOKEN("virtual")) {
	         **         if (saw & LVS_SAW_FAILOVERSERVICE)
	         **             return LVS_ERROR_ONLYONESERVICE;
	         **         else
	         **             saw |= LVS_SAW_VIRTUALSERVICE;
	         **} else {
	         **         if (saw & LVS_SAW_VIRTUALSERVICE)
	         **             return LVS_ERROR_ONLYONESERVICE;
	         **         else
	         **             saw |= LVS_SAW_FAILOVERSERVICE;
	         **}       They are not both allowed at this time 
	         **
	         ** Now that a "service" flag exists, they CAN both exist
	         ** in the same file and we'll know what to do.
	       */

	      i = config->numVirtServers++;

	      config->virtServers = realloc (config->virtServers,
					     sizeof (*config->virtServers) *
					     config->numVirtServers);

	      lvsInitVirtualServer (&config->virtServers[i], toks.argv[1]);

	      if (eConfig)
		{
		  for (j = 0; j < eConfig->numVirtServers; j++)
		    if (!strcmp (eConfig->virtServers[j].name,
				 config->virtServers[i].name))
		      break;
		  if (j == eConfig->numVirtServers)
		    j = -1;
		  else
		    {
		      outputString (ob, &toks, 1,
				    eConfig->virtServers[j].name);
		      if (sectionMarkers)
			sectionMarkers[j] = 1;
		    }
		}
	      else
		{
		  j = -1;
		}

	      if (j == -1 && ob)
		ob->block++;

	      if (TOKEN ("failover"))
		config->virtServers[i].failover_service = -1;

	      rc = parseVirtualServer (fs, ob, config->virtServers + i,
				       j ==
				       -1 ? NULL : eConfig->virtServers + j);

	      if (j == -1 && ob)
		ob->block--;
	      if (rc)
		return rc;

	    }
	  else
	    return LVS_ERROR_BADCOMMAND;

	  freeTokens (&toks);
	  rc = getNextToks (fs, ob, &toks);
	  if (rc)
	    return rc;
	}


      /* This whole next section is not normally executed except when
         being called with eConfig */

      if (eConfig)
	{
	  if (!(saw & LVS_SAW_PRIMARYSERVER))
	    outputFormat (ob, (char *) "primary = %s\n",
			  eConfig->primaryServerName);

	  OUTPUT_MISSING_NUM (LVS_SAW_SERIAL_NO, eConfig->serial_no,
			      0, (char *) "serial_no = %d\n");

	  OUTPUT_MISSING_STR (LVS_SAW_PRIMARYPRIVATE,
			      eConfig->primaryPrivateName, "",
			      "primary_private = %s\n");

	  OUTPUT_MISSING_STR (LVS_SAW_PRIMARYSHARED, eConfig->primaryShared,
			      "", "primary_shared = %s\n");

	  OUTPUT_MISSING_STR (LVS_SAW_RCA,
			      eConfig->reservation_conflict_action, "",
			      "reservation_conflict_action = %s\n");

	  OUTPUT_MISSING_NUM (LVS_SAW_BACKUPACTIVE, eConfig->backupActive,
			      0, (char *) "backup_active = %d\n")
	    if (!(saw & LVS_SAW_BACKUPSERVER) && eConfig->backupServerName)
	    outputFormat (ob, (char *) "backup = %s\n",
			  eConfig->backupServerName);

	  OUTPUT_MISSING_STR (LVS_SAW_BACKUPPRIVATE,
			      eConfig->backupPrivateName, "",
			      "backup_private = %s\n");

	  OUTPUT_MISSING_STR (LVS_SAW_BACKUPSHARED, eConfig->backupShared,
			      "", "backup_shared = %s\n");

	  if (*((int *) &eConfig->natRouter) && !(saw & LVS_SAW_NATROUTER))
	    outputFormat (ob, (char *) "nat_router = %s %s\n",
			  inet_ntoa (eConfig->natRouter),
			  eConfig->natRouterDevice);

	  OUTPUT_MISSING_STR (LVS_SAW_ACTIVE_CMD,
			      eConfig->activeCommand, "",
			      "active_cmd = %s\n");

	  OUTPUT_MISSING_STR (LVS_SAW_INACTIVE_CMD,
			      eConfig->inactiveCommand, "",
			      "inactive_cmd = %s\n");

	  OUTPUT_MISSING_STR (LVS_SAW_RSHCOMMAND, eConfig->rshCommand,
			      (char *) "rsh", (char *) "rsh_command = %s\n")
	    OUTPUT_MISSING_STR (LVS_SAW_DEBUG_LEVEL, eConfig->debug_level,
				(char *) "debug_level",
				(char *) "debug_level = %s\n")
	    OUTPUT_MISSING_STR (LVS_SAW_VSADM, eConfig->vsadm,
				(char *) IPVSADM,
				(char *) "ipvsadm = %s\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_USESYNCDAEMON, eConfig->useSyncDaemon,
				0,
				(char *) "syncdaemon = %d\n")
	    OUTPUT_MISSING_STR (LVS_SAW_SYNCD_IFACE, eConfig->syncdInterface,
				(char *) "syncd_iface",
				(char *) "syncd_iface = %s\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_SYNCD_ID, eConfig->syncdID,
				0,
				(char *) "syncd_id = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_TCP_TIMEOUT, eConfig->tcpTimeout,
				0,
				(char *) "tcp_timeout = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_TCPFIN_TIMEOUT, eConfig->tcpfinTimeout,
				0,
				(char *) "syncd_id = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_UDP_TIMEOUT, eConfig->udpTimeout,
				0,
				(char *) "syncd_id = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_USEHEARTBEAT, eConfig->useHeartbeat,
				0,
				(char *) "heatbeart = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_KEEPALIVETIME, eConfig->keepAliveTime,
				2,
				(char *) "keepalive = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_DEADTIME, eConfig->deadTime, 5,
				(char *) "deadtime = %d\n")
	    OUTPUT_MISSING_NUM (LVS_SAW_USEFILESYNC, eConfig->useFileSync, 0,
				(char *) "sync = %d\n") if (!(saw &
							      LVS_SAW_REDIRECTTYPE)
							    && (eConfig->
								redirectType
								!=
								LVS_REDIRECT_NAT))
	    {
	      if (eConfig->redirectType == LVS_REDIRECT_TUNNEL)
		outputFormat (ob, (char *) "network = tunnel\n");
	      else if (eConfig->redirectType == LVS_REDIRECT_DIRECT)
		outputFormat (ob, (char *) "network = direct\n");
	    }


	  if (!(saw & LVS_SAW_SERVICETYPE))
	    {
	      if (eConfig->lvsServiceType != LVS_SERVICE_TYPE_FOS)
		outputFormat (ob, (char *) "service = lvs\n");
	      else
		outputFormat (ob, (char *) "service = fos\n");
	    }


	  /* trim trailing '\n's (these can be left over when virtual servers
	     are eliminated */

	  current_ptr = ob->end - 1;
	  while (*current_ptr == '\n' && current_ptr != ob->text)
	    *current_ptr-- = '\0';
	  current_ptr++;
	  *current_ptr++ = '\n';
	  ob->len = current_ptr - ob->text;
	  ob->end = current_ptr;

	  for (i = 0; i < eConfig->numVirtServers; i++)
	    {
	      if (!sectionMarkers[i])
		{
		  outputFormat (ob, (char *) "\nvirtual %s {\n",
				eConfig->virtServers[i].name);
		  outputVirtualServer (ob, eConfig->virtServers + i, 0, 1);
		  outputFormat (ob, (char *) "}\n");
		}
	    }
	}

      if ((saw & LVS_SAW_PRIMARYSERVER) && !(saw & LVS_SAW_PRIMARYPRIVATE))
	{
	  memcpy (&config->primaryPrivate, &config->primaryServer,
		  sizeof (config->primaryServer));
	  config->primaryPrivateName = strdup (config->primaryServerName);
	  memcpy (&config->backupPrivate, &config->backupServer,
		  sizeof (config->backupServer));
	  config->backupPrivateName = config->backupServerName ?
		  			strdup (config->backupServerName) :
					NULL;
	}

      return 0;
    }



/*
**  lvsRelocateFS()
**
**  Moves the Failover Service pointers from the Virtual Server List
**  to their own private list -- making both lists pure. This routine
**  can be called multiple times to move items later added to the
**  virtual server list.
*/

  void lvsRelocateFS (struct lvsConfig *config)
  {

    int i = 0;
    int j;

    if (config == NULL)
      return;			/* No pointer? */
    else if (config->numVirtServers == 0)
      return;			/* No virtual servers to process */


    while (i < config->numVirtServers)
      {

	if (config->virtServers[i].failover_service)
	  {
	    /* found one */

	    j = config->numFailoverServices++;

	    config->failoverServices = realloc (config->failoverServices,
						sizeof (*config->
							failoverServices) *
						config->numFailoverServices);
	    /* Allocate memory */

	    memcpy (&config->failoverServices[j], &config->virtServers[i],
		    sizeof (*config->failoverServices));
	    /* Copy item into failover service list */

	    for (j = i; j < config->numVirtServers - 1; ++j)
	      config->virtServers[j] = config->virtServers[j + 1];
	    /* Move the virtual server list over one element */

	    config->numVirtServers--;
	  }
	else
	  ++i;
      }

    return;
  }




/*
** lvsParseConfig()
**
** MAIN ENTRY POINT. This routine reads in the whole config file, sets
** defaults, and calls other parser routines to fill in the lvsConfig
** structure values.
**
** Passed:
**     fd		 file descriptor of file
**     config		 pointer to lvsConfig structure to fill.
**
** Returned:
**     badLineNum	 line number of unparsed bad line in file.
**     lvsParseConfig()	 Completion status
*/

  int lvsParseConfig (int fd, struct lvsConfig *config, int *badLineNum)
  {
    struct stat sb;
    struct fileState configFile;
    int rc;

    *badLineNum = 0;
    memset (config, 0, sizeof (*config));	/* Zero out structure */

    fstat (fd, &sb);
    if (!sb.st_size)
      {
	return LVS_ERROR_STAT;
	/* File was zero length */
      }

    configFile.contents = alloca (sb.st_size + 2);

    if (read (fd, configFile.contents, sb.st_size) != sb.st_size)
      return LVS_ERROR_READ;	/* Read in entire file */

    configFile.contents[sb.st_size] = '\n';	/* just to be sure */
    configFile.contents[sb.st_size + 1] = '\0';
    configFile.lineNum = 0;
    configFile.thisLine = NULL;
    configFile.lineEnd = NULL;

    /* Set default values */
    config->useSyncDaemon = 0;
    config->syncdInterface = strdup ("eth0");
    config->syncdID = 0;
    config->useHeartbeat = 0;
    config->heartbeatPort = 539;
    config->keepAliveTime = 2;
    config->deadTime = 5;
    config->rshCommand = strdup ("rsh");
    config->debug_level = strdup ("NONE");
    config->useFileSync = 0;
    config->lvsServiceType = 0;
    config->vsadm = strdup (IPVSADM);	/* from globals.h */
    config->reserve = strdup (RESERVE);	/* from globals.h */
    config->redirectType = LVS_REDIRECT_NAT;
    config->hardShutdown = 1;
    config->tcpTimeout = 0;
    config->tcpfinTimeout = 0;
    config->udpTimeout = 0;

    rc = parseConfiguration (&configFile, NULL, config, NULL);

    if (rc)
      *badLineNum = configFile.lineNum;

    return rc;
  }




  int lvsMergeConfig (int fd, int outfd,
		      struct lvsConfig *config, int *badLineNum)
  {

    struct stat sb;
    struct fileState configFile;
    int rc;
    struct outputBuffer outputBuffer;
    struct lvsConfig cfg;

    fstat (fd, &sb);

    if (!sb.st_size)
      {
	return LVS_ERROR_STAT;
	/* File was zero length */
      }

    configFile.contents = alloca (sb.st_size + 2);

    if (read (fd, configFile.contents, sb.st_size) != sb.st_size)
      return LVS_ERROR_READ;

    configFile.contents[sb.st_size] = '\n';	/* just to be sure */
    configFile.contents[sb.st_size + 1] = '\0';
    configFile.lineNum = 1;
    configFile.thisLine = NULL;
    configFile.lineEnd = NULL;

    outputBuffer.text = malloc (200);
    *outputBuffer.text = '\0';
    outputBuffer.len = 0;
    outputBuffer.block = 0;
    outputBuffer.alloced = 200;
    outputBuffer.end = outputBuffer.text;

    memset (&cfg, 0, sizeof (cfg));

    rc = parseConfiguration (&configFile, &outputBuffer, &cfg, config);

    if (rc)
      *badLineNum = configFile.lineNum;
    else
      {
	lseek (outfd, 0, SEEK_SET);
	if (write (outfd, outputBuffer.text, outputBuffer.len) !=
	    outputBuffer.len)
	  rc = 1;
	ftruncate (outfd, outputBuffer.len);
      }

    free (outputBuffer.text);
/*
**  Leave this block commented out -- breaks merge config
**  if (rc == 0)
**	lvsRelocateFS(config);
*/

    return rc;
  }



/*
** lvsFreeConfig() -- Free dynamically allocated members in the config
*/

#define FREE(x)  if (x) free(x)

static inline void lvsFreeService(struct lvsService *service)
{
	FREE(service->name);
	FREE(service->logFile);
}

static inline void lvsFreeVirtServer(struct lvsVirtualServer *vserver)
{
	int i;

	FREE(vserver->name);
	FREE(vserver->virtualDevice);
	FREE(vserver->clientMonitor);
	FREE(vserver->send_program);
	FREE(vserver->send_str);
	FREE(vserver->expect_str);
	FREE(vserver->loadMonitor);
	FREE(vserver->start_cmd);
	FREE(vserver->stop_cmd);

	for (i = 0; i < vserver->numServers; i++)
		lvsFreeService(vserver->servers + i);
	FREE(vserver->servers);
}

void lvsFreeConfig (struct lvsConfig *config)
{
	int i;

	FREE(config->primaryServerName);
	FREE(config->primaryPrivateName);
	FREE(config->primaryShared);
	FREE(config->backupServerName);
	FREE(config->backupPrivateName);
	FREE(config->backupShared);
	FREE(config->natRouterDevice);
	FREE(config->rshCommand);
	FREE(config->debug_level);
	FREE(config->vsadm);
	FREE(config->reserve);
	FREE(config->reservation_conflict_action);
	FREE(config->activeCommand);
	FREE(config->inactiveCommand);

	for (i = 0; i < config->numVirtServers; i++)
		lvsFreeVirtServer(config->virtServers + i);
	FREE(config->virtServers);

	for (i = 0; i < config->numFailoverServices; i++)
		lvsFreeVirtServer(config->failoverServices + i);
	FREE(config->failoverServices);
}


/*
** lvsStrerror() -- Returns error string for lvs error code.
*/

  const char *lvsStrerror (int rc)
  {

    switch (rc)
      {

      case LVS_ERROR_BADQUOTING:
	return "quotation mismatch";

      case LVS_ERROR_EOF:
	return "unexpected end of file";

      case LVS_ERROR_EXTRAARGS:
	return "unexpected arguments";

      case LVS_ERROR_EQUALEXPECTED:
	return "equal (=) expected after command";

      case LVS_ERROR_MISSINGARGS:
	return "missing arguments";

      case LVS_ERROR_BADHOSTNAME:
	return "invalid host name or ip address";

      case LVS_ERROR_BADARGUMENT:
	return "invalid argument";

      case LVS_ERROR_INTEXPECTED:
	return "integer expected";

      case LVS_ERROR_BOOLEXPECTED:
	return "boolean expected";

      case LVS_ERROR_BADCOMMAND:
	return "unknown command";

      case LVS_ERROR_LISTEXPECTED:
	return "list expected";

      case LVS_ERROR_ONLYONESERVICE:
	return "Cannot use both virtual AND failover services";

      case LVS_ERROR_BADNETMASK:
	return "Bad subnet mask specified";

      case LVS_ERROR_STAT:
        return "Empty configuration";

      case LVS_ERROR_READ:
        return "I/O error while reading configuration";
      }

    return "unknown error";
  }




  void lvsInitVirtualServer (struct lvsVirtualServer *vs, const char *name)
  {
    memset (vs, 0, sizeof (*vs));
    vs->name = strdup (name);
    vs->protocol = IPPROTO_TCP;
    vs->port = 80;		/* http */
/*    vs->vip_nmask	    = NULL; */
    vs->scheduler = LVS_SCHED_WLC;
    vs->timeout = 10;
    vs->reentryTime = 180;
    vs->loadMonitor = NULL;
    vs->clientMonitor = strdup ("/usr/sbin/nanny");
    vs->send_program = NULL;
    vs->send_str = NULL;
    vs->expect_str = NULL;
    vs->failover_service = 0;
    vs->start_cmd = NULL;
    vs->stop_cmd = NULL;
    vs->persistent = 0;
  }
