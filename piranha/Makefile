#
#	Makefile for the Red Hat Piranha package 
#	(C) Red Hat, Inc. 1999 All rights reserved.
#
#	This program is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; either version 2 of the License, or
#	(at your option) any later version.
#
#	This program is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with this program; if not, write to the Free Software
#	Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

NAME		= piranha
VERSION 	= 0.8.6
RELEASE 	= 1
ARCH		= $(shell /bin/arch)
DATE		= $(shell date +%d/%b/%Y)

ME		= $(shell id -u )

# Note: There are also hard-coded values for this in the pulse init script,
#       piranha-gui init, and in the piranha spec file. We should tie these
#       all together.


#	I have to admit, I have a weakness for using the Compaq C compiler
#	on the Alpha because it can pick out 32/64 bit problems much more 
#	easily than gcc can. Least this way if CC is defined in the 
#	enviroment, it should override this hackery. - Phil Copeland

CC :=	$(shell if [ "$$CC" != "" ]; then echo $$CC; \
       		else if [ -x /usr/bin/ccc ]; then \
			echo "ccc"; \
		else \
			echo "gcc"; \
		fi ; fi)

#COPTS   	=

ifeq ($(CC),ccc)
		CFLAGS	= -Wall -g -O0 -frecord-gcc-switches -DVERSION=\"$(VERSION)\" -DRELEASE=\"$(RELEASE)\" -DDATE=\"$(DATE)\"
else 
		CFLAGS	= -Wall -g -O0 -frecord-gcc-switches -DVERSION=\"$(VERSION)\" -DRELEASE=\"$(RELEASE)\" -DDATE=\"$(DATE)\" -Wno-format
endif

LDFLAGS   	= -ggdb # -lefence
LOADLIBES 	= -lpopt -lm -lpthread -lrt -lssl -lcrypto
INCLUDE   	= 

SBIN	  	= $(DESTDIR)/usr/sbin
MANDIR	  	= $(DESTDIR)/usr/share/man
SYSDIR	  	= $(DESTDIR)/etc/rc.d/init.d
SYSCONFIGDIR	= $(DESTDIR)/etc/sysconfig
GNOMEDIR  	= $(DESTDIR)/usr/share/gnome/apps/System
KDEDIR    	= $(DESTDIR)/etc/X11/applnk/System
PIXMAPS   	= $(DESTDIR)/usr/share/pixmaps
HADIR     	= $(DESTDIR)/etc/sysconfig/ha
HALOG		= $(DESTDIR)/var/log/piranha
DOCS		= $(DESTDIR)/usr/share/doc/$(NAME)-$(VERSION)
LOGROTATEDIR	= $(DESTDIR)/etc/logrotate.d
INSTALL   	= install

#Location of libraries
DEFAULT_LIBDIR = /usr/lib
ifndef LIBDIR
LIBDIR := $(DEFAULT_LIBDIR)
endif

#Variables for building s/rpms
DEFAULT_RPM := $(shell if test -f /usr/bin/rpmbuild ; then echo rpmbuild ; else echo rpm ; fi)
DEFAULT_WORKDIR := $(shell pwd)/RPM

DEFAULT_SRCRPMDIR = $(WORKDIR)
DEFAULT_BUILDDIR = $(WORKDIR)
DEFAULT_RPMDIR = $(WORKDIR)
DEFAULT_SOURCEDIR = $(shell pwd)

## use defaults if user did not specify
ifndef WORKDIR
WORKDIR := $(DEFAULT_WORKDIR)
endif
ifndef SRCRPMDIR
SRCRPMDIR := $(DEFAULT_SRCRPMDIR)
endif
ifndef BUILDDIR
BUILDDIR := $(DEFAULT_BUILDDIR)
endif
ifndef RPMDIR
RPMDIR := $(DEFAULT_RPMDIR)
endif
ifndef SOURCEDIR
SOURCEDIR := $(DEFAULT_SOURCEDIR)
endif
ifdef OVERRIDE_RPM
RPM = $(OVERRIDE_RPM)
else
RPM = $(DEFAULT_RPM)
endif

# RPM with all the overrides in place
ifndef RPM_WITH_DIRS
RPM_WITH_DIRS = $(RPM) --define "_sourcedir $(SOURCEDIR)" --define "_srcrpmdir $(SRCRPMDIR)" --define "_builddir $(BUILDDIR)" --define "_rpmdir $(RPMDIR)"
endif

all:		explain lvsd fos pulse nanny send_arp pkglists infoAgent 

piranha:	all lvsconfig


explain:
ifeq ($(CC),ccc)
		@echo "--------------------------------------------------------------------------"
		@echo "Compaq C found, using it by preference (use \"export CC=gcc\" to override)"
		@echo "--------------------------------------------------------------------------"
endif
ifeq ($(CC),gcc)
		@echo "--------------------------------------------------------------------------"
		@echo "Assuming build with GNU C compiler"
		@echo "--------------------------------------------------------------------------"
endif


pkglists:


lvsd:		lvsd.o lvsconfig.o util.o ipvs_exec.o

fos:		fos.o lvsconfig.o util.o

nanny:		nanny.o util.o ipvs_exec.o

send_arp:	send_arp.c
		$(CC) $(CFLAGS) -o send_arp send_arp.c

pulse:		pulse.o lvsconfig.o util.o linkstate.o ipvs_exec.o

lvsconfig:	lvsconfig.o main.o 

infoAgent: infoAgent.o lvsconfig.o
	g++ -g infoAgent.o lvsconfig.o -lpthread -o infoAgent 
pulse.o: 	pulse.c lvsconfig.h util.h

linkstate.o:    linkstate.c

lvsd.o:  	lvsd.c lvsconfig.h util.h

fos.o:  	fos.c lvsconfig.h util.h

nanny.o:	nanny.c nanny.h

lvsconfig.o:	lvsconfig.c lvsconfig.h

util.o:		util.c

main.o:		main.c lvsconfig.h

infoAgent.o: infoAgent.c lvsconfig.h 

install: 	all

		mkdir -p $(SBIN) $(MANDIR)/man5 $(MANDIR)/man8 \
			$(SYSDIR) $(GNOMEDIR) $(KDEDIR) $(DOCS)\
			$(PIXMAPS) $(HADIR) $(HALOG) \
			$(LOGROTATEDIR)

		$(INSTALL) -m 0700 piranha-passwd $(SBIN)/
		$(INSTALL) -m 0755 lvsd $(SBIN)/
		$(INSTALL) -m 0755 fos $(SBIN)/
		$(INSTALL) -m 0755 pulse $(SBIN)/
		$(INSTALL) -m 0755 nanny $(SBIN)/
		$(INSTALL) -m 0755 send_arp $(SBIN)/
		$(INSTALL) -m 0644 lvsd.8 $(MANDIR)/man8/
		$(INSTALL) -m 0644 fos.8 $(MANDIR)/man8/
		$(INSTALL) -m 0644 lvs.cf.5 $(MANDIR)/man5/
		$(INSTALL) -m 0644 pulse.8 $(MANDIR)/man8/
		$(INSTALL) -m 0644 nanny.8 $(MANDIR)/man8/
		$(INSTALL) -m 0644 send_arp.8 $(MANDIR)/man8/
		$(INSTALL) -m 0755 pulse.init $(SYSDIR)/pulse
		$(INSTALL) -m 0644 pulse.sysconfig $(SYSCONFIGDIR)/pulse
		$(INSTALL) -m 0755 piranha-gui.init $(SYSDIR)/piranha-gui
		#$(INSTALL) -m 0755 example_script $(HADIR)/example_script

		#
		# Web Installation.

		ln -sf $(LIBDIR)/httpd/modules $(HADIR)/modules
		ln -sf /usr/sbin/httpd $(SBIN)/piranha_gui
		touch $(HALOG)/piranha-gui
		touch $(HALOG)/piranha-gui-access

		#
		# Install as 755 so that dirs are created correctly.
		#

		$(INSTALL) -d -m 0755 web $(HADIR)
		$(INSTALL) -d -m 0755 web/logs $(HADIR)/logs
		$(INSTALL) -d -m 0755 web/conf $(HADIR)/conf
		$(INSTALL) -d -m 0755 web/web $(HADIR)/web
		$(INSTALL) -d -m 0755 web/web/secure $(HADIR)/web/secure
		$(INSTALL) -m 0755 active.sh $(HADIR)/active.sh
		$(INSTALL)  -m 0755 inactive.sh $(HADIR)/inactive.sh
		$(INSTALL)  -m 0755 getactive.sh $(HADIR)/getactive.sh
		$(INSTALL)  -m 0755 healthstatus.sh $(HADIR)/healthstatus.sh
		$(INSTALL)  -m 0755 piranhahttp.sh  $(HADIR)/piranhahttp.sh
		$(INSTALL) -m 0755 infoAgent $(HADIR)/infoAgent
		
		#
		# Install web files.
		#

		$(INSTALL) -m 644 web/conf/httpd.conf		$(HADIR)/conf/httpd.conf
		$(INSTALL) -m 644 web/logrotate/piranha-httpd	$(LOGROTATEDIR)/
		$(INSTALL) -m 644 web/logs/README		$(HADIR)/logs/README

		$(INSTALL) -m 644 web/web/favicon.ico		$(HADIR)/web/favicon.ico
		$(INSTALL) -m 644 web/web/about_login.php	$(HADIR)/web/about_login.php
		$(INSTALL) -m 644 web/web/cluster_logo.gif	$(HADIR)/web/cluster_logo.gif
		$(INSTALL) -m 644 web/web/docs.html		$(HADIR)/web/docs.html
		$(INSTALL) -m 644 web/web/index.html		$(HADIR)/web/index.html
		$(INSTALL) -m 644 web/web/RedHat.gif		$(HADIR)/web/RedHat.gif
		$(INSTALL) -m 644 web/web/secure/control.php	$(HADIR)/web/secure/control.php
		$(INSTALL) -m 644 web/web/secure/help.css	$(HADIR)/web/secure/help.css

		#
		# Avoid the CVS dir if it exists.
		#

		$(INSTALL) -m 644 web/web/secure/*.php		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.html		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.jpg	$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.png		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.PNG		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.gif		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.css		$(HADIR)/web/secure
		$(INSTALL) -m 644 web/web/secure/*.js		$(HADIR)/web/secure

		#
		# typically the .htaccess file always gets forgotten.
		#

		#$(INSTALL) -m 644 web/web/secure/.htaccess	$(HADIR)/web/secure/.htaccess


		if [ -s $(DESTDIR)/etc/lvs.cf ] && [ ! -s $(HADIR)/lvs.cf ]; then \
			echo "# This file was created from your original lvs.cf in /etc" \
				>  $(HADIR)/lvs.cf ;\
			echo >> $(HADIR)/lvs.cf ;\
			cat $(DESTDIR)/etc/lvs.cf >> $(HADIR)/lvs.cf ;\
			rm -f $(DESTDIR)/etc/lvs.cf ;\
		fi;

		$(INSTALL) -m 664 lvs.cf  $(HADIR)/lvs.cf
		#
		# Just make sure lvs.cf exists.
		#

		touch $(HADIR)/lvs.cf


		#
		# Ok, better make sure the file permissions are correct.
		# owner,group stuff is irrelevant at this point
		#

		chmod 664 $(HADIR)/lvs.cf
		chmod 775 $(HALOG)
		chmod 644 $(HADIR)/conf/httpd.conf
		chmod 644 $(HADIR)/web/*
		chmod 755 $(HADIR)/web/secure
		chmod 644 $(HADIR)/web/secure/*
		chmod 755 $(HADIR)
		chmod 664 $(HALOG)/piranha-gui
		chmod 664 $(HALOG)/piranha-gui-access

		#
		# This is so that we can install as a standalone compile
		# or as part of the distribution build system.
		# If we are root, we are probably not in the build system
		# which means we are being installed as root from the Makefile.
		# Assume that we have to setup the ownerships and groups
		# 
		# If we are not root then DO NOT do this. The rpm spec file will handle it
		# (I hope)
		#

		if [ $(ME) = 0 ]; then \
			/usr/sbin/groupadd -g 60 -r -f piranha > \
				/dev/null 2>&1 ||:			;\
			/usr/sbin/useradd -u 60 -g 60 -d \
				/etc/sysconfig/ha -r -s \
				/dev/null piranha >/dev/null 2>&1 ||:	;\
			chown root.piranha $(HADIR)/lvs.cf 		;\
			chown root.piranha $(HALOG)			;\
			chown root.nobody $(HADIR)/conf/httpd.conf	;\
			chown -R root.piranha $(HADIR)/web		;\
			chown root.piranha $(HALOG)/piranha-gui		;\
			chown root.piranha $(HALOG)/piranha-gui-access	;\
		fi
		
		
		#
		# Lastly, copy the documentation to the right place
		#

		cp -prR docs/* $(DOCS)

clean:
		rm -f nanny lvsd lvsconfig fos pulse piranha.spec *.o *.bak \
		piranha-*.tar.gz send_arp cf
		rm -rf RPM
		mkdir RPM
		rm -f `find -name "*~"`
		rm -f `find -name "core"`

dist:		clean
		sed -e "s/@@VERSION@@/$(VERSION)/g" <piranha.spec.in >piranha.spec.tmp
		sed -e "s/@@RELEASE@@/$(RELEASE)/g" <piranha.spec.tmp >piranha.spec
		rm -f piranha.spec.tmp
		( cd .. ; tar czvf piranha-$(VERSION).tar.gz \
			--exclude CVS  \
			--exclude gui  \
			--exclude misc \
			--exclude foo \
			--exclude LVS_HOWTO \
			--exclude '.*.swp' \
		piranha ; \
		mv $(NAME)-$(VERSION).tar.gz piranha ; cd piranha)

rpms:		dist
		$(RPM_WITH_DIRS) -ba $(NAME).spec

srpm:		dist
		$(RPM_WITH_DIRS) --nodeps -bs $(NAME).spec
