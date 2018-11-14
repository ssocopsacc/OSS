/* Red Hat Clustering Tools 
 * Copyright 1999 Red Hat, Inc.
 *
 * Author: Erik Troan <ewt@redhat.com> 
 *
 *
 * This software may be freely redistributed under the terms of the GNU
 * public license.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 *
 * MODIFICATION HISTORY:
 *
 * 2/28/2000    Keith Barrett <kbarrett@redhat.com>
 *              Added typecasts to make strict compiles happier
 *
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "util.h"

char *name = NULL;

void
logName (char *newName)
{
  name = newName;
}

static void
doSyslog (char *format, va_list args)
{
  int bufLen = 80;
  char *buf = malloc (bufLen);
  int ret;

  while (1)
    {
      va_list try_args;
      va_copy(try_args, args);
      ret = vsnprintf (buf, bufLen, format, try_args);
      va_end(try_args);
      if ((ret > -1) && (ret < bufLen))
	{
	  break;
	}
      else
	{
	  bufLen += 80;
	  buf = realloc (buf, bufLen);
	}
    }

  syslog (LOG_INFO, buf);

  free (buf);
}

/* formally known as 'log' which unfortunately is reserved in the math 
 * library. renamed to piranha_log
 */
void
piranha_log (int flags, char *format, ...)
{
  char logmsg[256];
  char totalmsg[320];

  va_list args;

  if (flags & LVS_FLAG_PRINTF)
    {
      va_start (args, format);
      vsnprintf (logmsg, sizeof(logmsg), format, args);
      snprintf(totalmsg, sizeof(totalmsg), "%s: %s\n", name, logmsg);
      write(STDOUT_FILENO, totalmsg, strlen(totalmsg));
      va_end (args);
    }
  if (flags & LVS_FLAG_SYSLOG)
    {
      va_start (args, format);
      doSyslog (format, args);
      va_end (args);
    }
}


int
daemonize (int flags)
{
  pid_t child;
  FILE *f;
  char pidFile[80];

  if (!(flags & LVS_FLAG_NOFORK))
    {
      child = fork ();
      if (!child)
	{
	  child = fork ();
	  if (child)
	    exit (0);
	}
      else
	{
	  waitpid (child, NULL, 0);
	  return 1;
	}
    }

  if (!(flags & LVS_FLAG_NOPIDFILE))
    {
      sprintf (pidFile, "/var/run/%s.pid", name);
      f = fopen (pidFile, "w");
      if (!f)
	{
	  piranha_log (flags,
		       (char *) "failed to open %s: %s", pidFile,
		       strerror (errno));
	}
      else
	{
	  fprintf (f, "%d\n", getpid ());
	  fclose (f);
	}
    }

  if (!(flags & LVS_FLAG_PRINTF))
    {
      close (0);
      close (1);
      close (2);
      open ("/dev/null", O_RDWR, 0);
      dup (0);
      dup (0);
      setsid ();
    }

  return 0;
}

void
logArgv (int flags, char **argv)
{
  char *argList;
  int len = 0;
  int i;

  for (i = 0; argv[i]; i++)
    len += strlen (argv[i]) + 3;
  argList = alloca (len + 1);
  *argList = '\0';

  for (i = 0; argv[i]; i++)
    {
      strcat (argList, " \"");
      strcat (argList, argv[i]);
      strcat (argList, "\"");
    }

/*	piranha_log (flags, (char *) "running command %s", argList); */
}
