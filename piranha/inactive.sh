#!/bin/sh
SCRIPTNAME="INACTIVE"
HASERVICESRESTARTLOGFILE=/home/fes/logs/haservicesrestart.log
lockdir=/tmp/inactive.lock
mkdir "${lockdir}" > /dev/null
ret=$?
if [ $ret == 0 ]; then
  echo `date` "[$SCRIPTNAME] [$$] Locking succeeded" >> $HASERVICESRESTARTLOGFILE
  trap 'rm -rf "$lockdir"; exit $?' INT TERM EXIT
else
  echo `date` "[$SCRIPTNAME] [$$] Lock failed. Inactive Script Already Running, Checking using kill." >> $HASERVICESRESTARTLOGFILE
  alreadyrunningpid=$(cat /tmp/inactivepid) >> $HASERVICESRESTARTLOGFILE 2>&1 
  kill -0 $alreadyrunningpid >> $HASERVICESRESTARTLOGFILE 2>&1
  if [ $? -eq 0 ]
  then
 	echo `date` "[$SCRIPTNAME] [$$] Inactive script already running." >> $HASERVICESRESTARTLOGFILE
	exit 0
  else
	echo `date` "[$SCRIPTNAME] [$$] Inactive script is found not running using kill command" >> $HASERVICESRESTARTLOGFILE
    	#/usr/bin/ps ax | grep inactive.sh | grep -v grep >> $HASERVICESRESTARTLOGFILE 2>&1
        #if [ $? -eq 0 ]
        #then
	#	echo `date` "[$SCRIPTNAME] Inactive script already running." >> $HASERVICESRESTARTLOGFILE
	#	exit 0
        #else
		#echo `date` "[$SCRIPTNAME] Inactive script is found not running using ps command. Removing lock file and restarting it." >> $HASERVICESRESTARTLOGFILE
		/usr/bin/rm -rf "$lockdir"
		mkdir "${lockdir}" > /dev/null		
	#fi	     
  fi		
fi

echo "$$" > /tmp/inactivepid

echo `date` "[$SCRIPTNAME] [$$] Inactive Script Started." >> $HASERVICESRESTARTLOGFILE

DEADTIMEOUT=`awk 'BEGIN{DEADTIME="NONE";gotoloop=0;} {if($1=="deadtime"){DEADTIME=$3}} END{printf("DeadtimeOut=%s",DEADTIME) > "/tmp/ipaddr";print DEADTIME;}' /etc/sysconfig/ha/lvs.cf`

echo `date` "[$SCRIPTNAME] [$$] Inactive Going In Sleep for $DEADTIMEOUT secs." >> $HASERVICESRESTARTLOGFILE
sleep $DEADTIMEOUT

pgrep commDemon
if [ $? != 0 ]; then
	pkill commDemon
	rm -rf /home/fes/commDemon.txt
	/home/fes/commDemon
fi

VIPADDRESS=`awk 'BEGIN{VIPADDRS="NONE";gotoloop=0;} {if($1== "virtual" ){if(gotoloop ==  0 ){gotoloop=1;} else{gotoloop=0;}} if(gotoloop == 1) { if ($1=="address"){VIPADDRS=$3;gotoloop=0;}} }END{printf("VIPADDRESS=%s",VIPADDRS) > "/tmp/ipaddr";print VIPADDRS;}' /etc/sysconfig/ha/lvs.cf`

echo `date` "[$SCRIPTNAME] [$$] Flushing ARP tables For Virtual IP Entry." >> $HASERVICESRESTARTLOGFILE


#Set net.ipv4.vs.expire_quiescent_template = 1 in the proc file 
#/etc/expire_quiescent_template.conf is used for setting net.ipv4.vs.expire_quiescent_template 
#It is used for session maintainence between active and backup servers
sysctl -p /etc/expire_quiescent_template.conf

/etc/init.d/arptables_jf stop >> $HASERVICESRESTARTLOGFILE
/usr/sbin/arptables-noarp-addr $VIPADDRESS start >> $HASERVICESRESTARTLOGFILE
/etc/init.d/arptables_jf save  >> $HASERVICESRESTARTLOGFILE
/sbin/chkconfig --level 2345 arptables_jf on  >> $HASERVICESRESTARTLOGFILE
/etc/init.d/arptables_jf start  >> $HASERVICESRESTARTLOGFILE

#echo `date` "[$SCRIPTNAME] Stopping local database service." >> /tmp/hanodestate.log
#/sbin/service mariadb restart

echo `date` "[$SCRIPTNAME] [$$] Removing VIP $VIPADDRESS." >> $HASERVICESRESTARTLOGFILE
/sbin/ifconfig `cat /etc/sysconfig/ha/lvs.cf | grep $VIPADDRESS | awk '{ print $4 }'` down

echo `date` "[$SCRIPTNAME] [$$] Removing temp files." >> $HASERVICESRESTARTLOGFILE
rm -rf /tmp/ipaddr

echo `date` "[$SCRIPTNAME] [$$] Stopping InfoAgent and FileSync" >> $HASERVICESRESTARTLOGFILE
/home/fes/SyncBinary Kill

sleep 7

echo `date` "[$SCRIPTNAME] [$$] Clearing IP tables" >> $HASERVICESRESTARTLOGFILE
/usr/sbin/iptables -t nat -F

echo `date` "[$SCRIPTNAME] [$$] Starting InfoAgent and FileSync" >> $HASERVICESRESTARTLOGFILE
rm -rf /home/fes/filesync.conf

/home/fes/SyncBinary InActive

service piranha-gui stop

rm -rf /tmp/inactive.lock

echo `date` "[$SCRIPTNAME] [$$] All serivces started fine." >> $HASERVICESRESTARTLOGFILE

echo `date` "[$SCRIPTNAME] [$$] Inactive command completed [VIP $VIPADDRESS]" >> $HASERVICESRESTARTLOGFILE
rm -rf "$lockdir"

exit 0

