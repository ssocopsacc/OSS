#!/bin/sh

lockdir=/tmp/active.lock
HASERVICESRESTARTLOGFILE=/home/fes/logs/haservicesrestart.log
SCRIPTNAME="ACTIVE"
mkdir "${lockdir}" & >/dev/null
ret=$?
if [ $ret == 0 ]; then
  echo `date` "[$SCRIPTNAME] [$$] File Locking succeeded." >> $HASERVICESRESTARTLOGFILE 
  trap 'rm -rf "$lockdir"; exit $?' INT TERM EXIT
else
  echo `date` "[$SCRIPTNAME] [$$] Lock failed. Active Script Already Running, checking using kill command." >> $HASERVICESRESTARTLOGFILE
  alreadyrunningpid=$(cat /tmp/activepid) >> $HASERVICESRESTARTLOGFILE 2>&1
  kill -0 $alreadyrunningpid >> $HASERVICESRESTARTLOGFILE 2>&1
  if [ $? -eq 0 ]
  then
        echo `date` "[$SCRIPTNAME] [$$] Active script already running." >> $HASERVICESRESTARTLOGFILE
        exit 0
  else
        echo `date` "[$SCRIPTNAME] [$$] Active script is found not running using kill command" >> $HASERVICESRESTARTLOGFILE
        #/usr/bin/ps ax | grep inactive.sh | grep -v grep >> $HASERVICESRESTARTLOGFILE 2>&1
        #if [ $? -eq 0 ]
        #then
        #       echo `date` "[$SCRIPTNAME] Inactive script already running." >> $HASERVICESRESTARTLOGFILE
        #       exit 0
        #else
                #echo `date` "[$SCRIPTNAME] Inactive script is found not running using ps command. Removing lock file and restarting it." >> $HASERVICESRESTARTLOGFILE
                /usr/bin/rm -rf "$lockdir"
                mkdir "${lockdir}" > /dev/null
        #fi
  fi
fi

echo "$$" > /tmp/inactivepid
echo `date` "[$SCRIPTNAME] [$$] Active script called." >> $HASERVICESRESTARTLOGFILE

for i in `pgrep inactive`
do 
	kill -15 $i
	echo `date` "[$SCRIPTNAME] [$$] Kill Inactive script." >> $HASERVICESRESTARTLOGFILE
done
rm -rf /tmp/inactive.lock

pgrep commDemon
if [ $? != 0 ]; then
        pkill commDemon
        rm -rf /home/fes/commDemon.txt
        /home/fes/commDemon
fi

VIPADDRESS=`awk 'BEGIN{VIPADDRS="NONE";gotoloop=0;} {if($1== "virtual" ){if(gotoloop ==  0 ){gotoloop=1;} else{gotoloop=0;}} if(gotoloop == 1) { if ($1=="address"){VIPADDRS=$3;gotoloop=0;}} }END{printf("VIPADDRESS=%s",VIPADDRS) > "/tmp/ipaddr";print VIPADDRS;}' /etc/sysconfig/ha/lvs.cf`

echo `date` "[$SCRIPTNAME] [$$] Flushing ARP tables, iptables." >> $HASERVICESRESTARTLOGFILE

/etc/init.d/arptables_jf stop
arptables -F
iptables -t nat -F

echo `date` "[$SCRIPTNAME] [$$] Stopping FileSync and InfoAgent." >> $HASERVICESRESTARTLOGFILE

/home/fes/SyncBinary Kill
if [ $? != 0 ]; then
	echo `date` "[$SCRIPTNAME] [$$] Failed To Stop Agents. Check If CommandDaemon Is Running."	
fi

sleep 7

echo `date` "[$SCRIPTNAME] [$$] Starting FileSync And InfoAgent daemons." >> $HASERVICESRESTARTLOGFILE

rm -rf /home/fes/filesync.conf

#Set net.ipv4.vs.expire_quiescent_template = 1 in the proc file 
#/etc/expire_quiescent_template.conf is used for setting net.ipv4.vs.expire_quiescent_template 
#It is used for session maintainence between active and backup servers
sysctl -p /etc/expire_quiescent_template.conf

/home/fes/SyncBinary Active
if [ $? != 0 ]; then
        echo `date` "[$SCRIPTNAME] [$$] Failed To Start Agents. Check If CommandDaemon Is Running." >> $HASERVICESRESTARTLOGFILE
fi

arp -d $VIPADDRESS

#echo `date` "[$SCRIPTNAME] Restarting Mariadb service." >> $HASERVICESRESTARTLOGFILE
#service mariadb restart

#file=/home/fes/HANode.txt
#if [ -f $file ];
#then
#for i in `pgrep fes`
#do 
#	kill -15 $i
#	echo `date` "[$SCRIPTNAME] Killing fes" >> /tmp/hanodestate.log
#done

#sleep 1
#confirm fes is killed
#pkill fes


#start fes 
#/home/fes/fes /home/fes/
#if [ $? != 0 ]; then
#        echo "Failed to start fes"
#	/home/fes/fes /home/fes/
#fi
#rm -rf /home/fes/HANode.txt
#sleep 1

#confirm fes is started 
#/home/fes/fes /home/fes/
#fi

rm -rf /tmp/inactive.lock

echo `date` "[$SCRIPTNAME] [$$] Restarting PiranhaGui service." >> $HASERVICESRESTARTLOGFILE
service piranha-gui restart > /dev/null 2>&1

echo `date` "[$SCRIPTNAME] [$$] All services started." >> $HASERVICESRESTARTLOGFILE
rm -rf "$lockdir"

echo `date` "[$SCRIPTNAME] [$$] Active command finished by master LVD [$VIPADDRESS]." >> $HASERVICESRESTARTLOGFILE

exit 0
