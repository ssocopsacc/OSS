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
**  ??/??/1999  1.0     Erik Troan <ewt@redhat.com>
**                      Original release
**
**  5/31/2001   1.1     Keith Barrett <kbarrett@redhat.com>
**                      Missing include file. Display err #.
*/

#include <stdlib.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

#include "lvsconfig.h"

int
main (int argc, char **argv)
{

  int fd;
  int rc;
  struct lvsConfig config;
  int line;

  fd = open ("cf", O_RDONLY);

  if (fd < 0)
    {
      perror ("open");
      exit (1);
    }

  rc = lvsParseConfig (fd, &config, &line);

  if (rc)
    {
      printf ("error %d on line %d: %s\n", rc, line, lvsStrerror (rc));

    }
  else
    {
      lseek (fd, SEEK_SET, 0);
      lvsMergeConfig (fd, 1, &config, &line);
    }

  return 0;
}
