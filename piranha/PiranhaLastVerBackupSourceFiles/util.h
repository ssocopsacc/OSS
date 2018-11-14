/*
** util.h -- utility definitions file for piranha 
**
** Red Hat Clustering Tools 
** Copyright 1999 Red Hat, Inc.
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
** 09/1999      Erik Troan <ewt@redhat.com>
**              Mike Wangsmo <wanger@redhat.com>
**	            Original piranha release
**
** 01/28/2000   Keith Barrett <kbarrett@redhat.com>
**	            Added header & history
**
** 3/1/2000     Keith Barrett <kbarrett@redhat.com>
**              Added flags
**
*/

#ifndef H_PIRANHA_UTIL
#define H_PIRANHA_UTIL

#include <sys/types.h>

pid_t daemonize (int flags);
void piranha_log (int flags, char *format, ...);
void logArgv (int flags, char **argv);
void logName (char *name);

#define LVS_FLAG_TESTSTARTS     (1 << 26)
#define LVS_FLAG_ASDAEMON       (1 << 27)
#define LVS_FLAG_NOPIDFILE	(1 << 28)
#define LVS_FLAG_NOFORK		(1 << 29)
#define LVS_FLAG_SYSLOG		(1 << 30)
#define LVS_FLAG_PRINTF		(1 << 31)

#endif
