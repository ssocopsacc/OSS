/*
** nanny.h : Definitions file for nanny process
**
** Red Hat Clustering Tools 
** Copyright 1999 Red Hat, Inc.
**
** Author:	Keith Barrett <kbarrett@redhat.com>
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
** 	1/14/2000   1.0 	Keith Barrett <kbarrett@redhat.com>
**                  	Initial creation
*/


#ifndef _NANNY_H
#define _NANNY_H


#define NANNY_FLAG_ASDAEMON    (1 << 0)
#define NANNY_FLAG_NORUN       (1 << 1)
#define NANNY_FLAG_VERBOSE     (1 << 2)
#define NANNY_FLAG_REGEX       (1 << 3)

#define MAX_DUP_CHK            (8 * 128)

#define STATE_NORMAL           1
#define STATE_UP               2
#define STATE_DOWN             3

#define DEFDATALEN             (64 - 8)	/* Default data length */

#define SERV_UNK		0
#define SERV_FOS		1
#define SERV_LVS		2

#endif
