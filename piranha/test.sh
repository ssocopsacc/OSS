#!/bin/bash
vip_file="/home/fes/vip_feature_status.txt"
if [ -f $vip_file ]; 
then
#vip_status=cat $vip_file 
if [ $vip_statu == "Enabled" ]; then
vipservice_pid=pgrep /home/fes/manageVipforcluster
kill -9 $vipservicei_pid
pkill /home/fes/manageVipforcluster
sleep 10
/home/fes/manageVipforcluster
fi
fi
