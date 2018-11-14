#!/bin/bash


count=0
echo -e "$(/etc/sysconfig/ha/getactive.sh)"
echo -e "\n\n\x1b[4mPrinting status of all services:\e[0m\n"

RETVAL=`pgrep progeneric | wc -l`
echo -e "\n Count of VPN worker daemons(progeneric) is $RETVAL\n"

/usr/bin/pgrep commDemon > /dev/null 2>&1
if [ $? != 0 ]
then
	count=$((count+1))
	echo -e "\e[1;31m Service COMMAND-DAEMON NOT running\e[0m\n"
else
	echo -e " Service COMMAND-DAEMON is running\n"
fi

outstr=`pgrep infoAgent`
if [ $? != 0 ]
then
	count=$((count+1))
	echo -e "\e[1;31m Service INFOAGENT NOT running\e[0m\n"
else
	pidstr=`echo "$outstr" | tr '\n' ' ' | awk '{ printf("parent-pid %s, child-pid %s",$1,$2) }'`
	echo -e " Service INFOAGENT($pidstr) is running\n"
	
	outstr=`ps ax | grep infoAgent | awk 'FNR == 1 { print $6;}'`

	if [ $? == 0 ]
	then
        	if [[ "$outstr" == "Active" ]]
        	then
                 	echo -e " Service INFOAGENT is running in ACTIVE mode\n"
        	elif [[ "$outstr" == "" ]]
        	then
                	echo -e " Service INFOAGENT is running in PASSIVE mode\n"
        	fi
	fi
fi

outstr=`pgrep FileSync`
if [ $? != 0 ]
then
	count=$((count+1))
	echo -e "\e[1;31m Service FILESYNC NOT running\e[0m\n"
else
	pidstr=`echo "$outstr" | tr '\n' ' ' | awk '{ printf("parent-pid %s, child-pid %s",$1,$2) }'`
	echo -e " Service FILESYNC($pidstr) is running\n"
fi

if [ -d /var/lib/mysql/fesdb ]
then
 /usr/bin/ps ax | grep pulse | grep -v grep > /dev/null 2>&1
 if [ $? -eq 0 ]
 then
  	echo -e " Pulse is running.\n"
 else
	count=$((count+1))
	echo -e "\e[1;31m Pulse is stopped.\e[0m\n"
 fi
fi

if [ -d /var/lib/mysql/fesdb ]
then
 /usr/bin/ps ax | grep mariadb | grep -v grep > /dev/null 2>&1
 if [ $? -eq 0 ]
 then
        echo -e " Mariadb is running.\n"
 else
	count=$((count+1))
        echo -e "\e[1;31m Mariadb is stopped.\e[0m\n"
 fi
fi

if [ -d /var/lib/mysql/fesdb ]
then
 /usr/bin/ps ax | grep ipvs-m | grep -v grep > /dev/null 2>&1
 if [ $? -eq 0 ]
 then
 	echo -e " ipvsadm is running in Master Mode.\n"
 else
	/usr/bin/ps ax | grep ipvs-b | grep -v grep > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
		echo -e " ipvsadm is running in Backup Mode.\n"
	else
		count=$((count+1))
		echo -e "\e[1;31m ipvsadm is NOT Running.\e[0m\n"	
	fi		
 fi
fi

/usr/bin/ps ax | grep fesdbsync | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
	echo -e " FES DB sync is running\n"
else
	count=$((count+1))
	echo -e "\e[1;31m FES DB sync is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep fesgeneric | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " FESGENERIC is running\n"
else
	count=$((count+1))	
        echo -e "\e[1;31m FESGENERIC is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep "/home/fes/fes" | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " FES is running\n"
else
	count=$((count+1))
        echo -e "\e[1;31m FES is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep dnsCache | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " dnsCache is running\n"
else
	count=$((count+1))
        echo -e "\e[1;31m dnsCache is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep fesidletimeout | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " fesidletimeout is running\n"
else
        count=$((count+1))
        echo -e "\e[1;31m fesidletimeout is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep feslicencevalidation | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " feslicencevalidation is running\n"
else
        count=$((count+1))
        echo -e "\e[1;31m feslicencevalidation is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep piranha_gui | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
        echo -e " Piranha GUI is running\n"
else
	count=$((count+1))
        echo -e "\e[1;31m Piranha GUI is NOT running\e[0m\n"
fi

/usr/bin/ps ax | grep feslogger | grep -v grep > /dev/null 2>&1
if [ $? -eq 0 ]
then
	netstat -naup | grep feslogger | grep -v grep > /dev/null 2>&1
	if [ $? -eq 0 ]
	then
        	echo -e " FES Logger is running"
		echo -e " Count of FES Loggers $(pgrep feslogger | wc -l)\n"
	else
		count=$((count+1))
		echo -e "\e[1;31m FES Logger is NOT running\e[0m\n"
	fi
else
	count=$((count+1))
        echo -e "\e[1;31m FES Logger is NOT running\e[0m\n"
fi

echo -e "\n\n\x1b[4mPrinting all services uptime:\e[0m\n"
ps ax | grep commDemon | grep -v grep > /dev/null 2>&1 && echo "command    daemon is running for $(ps -p `ps ax | grep commDemon | grep -v grep | awk '{print $1}'` -o etime=)"
ps ax | grep fesgeneric | grep -v grep > /dev/null 2>&1 && echo "fesgeneric daemon is running for $(ps -p `ps ax | grep fesgeneric | grep -v grep | awk '{print $1}'` -o etime=)"
if [ -d /var/lib/mysql/fesdb ]
then
	ps ax | grep pulse | grep -v grep > /dev/null 2>&1 && echo "pulse      daemon is running for $(ps -p `ps ax | grep pulse | grep -v grep | awk '{print $1}'` -o etime=)"
fi
ps ax | grep infoAgent | grep -v grep > /dev/null 2>&1 && echo "infoAgent  daemon is running for $(ps -p `ps ax | grep infoAgent | grep -v grep | tail -1 | awk '{print $1}'` -o etime=)"
ps ax | grep FileSync | grep -v grep > /dev/null 2>&1 && echo "FileSync   daemon is running for $(ps -p `ps ax | grep FileSync | grep -v grep | tail -1 | awk '{print $1}'` -o etime=)"
ps ax | grep fesdbsync | grep -v grep > /dev/null 2>&1 && echo "FesDBSync  daemon is running for $(ps -p `ps ax | grep fesdbsync | grep -v grep | awk '{print $1}'` -o etime=)"
ps ax | grep "/home/fes/fes" | grep -v grep > /dev/null 2>&1 && echo "Fes        daemon is running for $(ps -p `ps ax | grep "/home/fes/fes" | grep -v grep | awk '{print $1}'` -o etime=)"
ps ax | grep "feslogger" | grep -v grep > /dev/null 2>&1 && echo "FesLogger  daemon is running for $(ps -p `ps ax | grep "feslogger" | grep -v grep | awk '{print $1}' | head -1` -o etime=)"
ps ax | grep fesgeneric | grep -v grep > /dev/null 2>&1 && echo "Fesgeneric daemon is running for $(ps -p `ps ax | grep fesgeneric | grep -v grep | awk '{print $1}'` -o etime=)"

echo -e "\n\x1b[4mTCP Services Listening on ports:\e[0m\n"

/usr/bin/netstat -natp | grep -i "LISTEN" | awk  'BEGIN{ printf("%20s %20s %20s\n","PID/PROCESS-NAME","-------------->","IPADDRESS:PORT")}{ printf("\n%20s %20s %20s",$7,"-------------->",$4);}'

echo -e "\n\n\x1b[4mUDP Services Listening on ports:\e[0m\n"
/usr/bin/netstat -naup | grep 0.0.0.0:* | awk  'BEGIN{ printf("%20s %20s %20s\n","PID/PROCESS-NAME","-------------->","IPADDRESS:PORT")}{ printf("\n%20s %20s %20s",$6,"-------------->",$4);}'

if [ $count -eq 0 ]
then 
	echo -e "\n\nAll OK! Bye"
else
	echo -e "\n\n \e[1;31m$count services not running\e[0m"
	#if [  
fi
