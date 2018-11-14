#!/bin/sh

#if [ -x /etc/init.d/pulse ] ; then 
#
#	/etc/init.d/pulse status > /dev/null 2>&1
#	RETVAL=$?
#	if [ $RETVAL -ne 0 ] ; then 
#				
#		echo "Status   :Stopped"
#		exit 0;
#	fi
#fi


if [ -d /var/lib/mysql/fesdb ]
then
	VIPADDRESS= awk 'BEGIN{VIPADDRS="NONE";gotoloop=0;IF_NAMES="NONE";} {if($1== "virtual" ){if(gotoloop ==  0 ){gotoloop=1;} else{gotoloop=0;}} if(gotoloop == 1) { if ($1=="address"){VIPADDRS=$3;gotoloop=0; j=split($4,res_arr,":");IF_NAMES=res_arr[1];}} }END{printf("VIPADDRESS=%s\nIFNAME=%s",VIPADDRS,IF_NAMES) > "/tmp/ipaddr"; }' /etc/sysconfig/ha/lvs.cf
. /tmp/ipaddr

	#echo "$VIPADDRESS $IFNAME"
	ip addr sh dev $IFNAME | awk 'BEGIN {finalstr="Standby"}{j=split($2,arra1,"/"); if(arra1[1] == VIRTUALIPADDR){k=split($7,iname,":"); if(iname[1] != "lo"){finalstr="Active";}}}END{print "NodeType: "finalstr}' VIRTUALIPADDR=$VIPADDRESS 
	rm -rf /tmp/ipaddr
else
	echo "NodeType: Real VPN Server"
fi
