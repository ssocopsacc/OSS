#!/bin/sh
cat /tmp/rc.local | grep piranha-gui
REVAL=$?
if [ $REVAL -ne 0 ] ; then 

	echo " if [ -f /etc/sysconfig/ha/infoAgent ] ; then ">>/tmp/rc.local
	echo " /etc/sysconfig/ha/infoAgent & ">>/tmp/rc.local
	echo " fi  ">>/tmp/rc.local

fi
