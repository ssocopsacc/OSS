#!/bin/sh

InpArgs=$@

rm -rf /tmp/httpd.conf.back
cat  /etc/sysconfig/ha/conf/httpd.conf | awk '{if (($2 == "deny") &&($3 == "from")){printf("deny from all\n") >>"/tmp/httpd.conf.back"; }else if (($1 == "Allow") &&($2 == "from")){  printf("Allow from %s\n",myvar)>>"/tmp/httpd.conf.back";} else {print $0 >>"/tmp/httpd.conf.back";}}'  myvar="$InpArgs"
mv /tmp/httpd.conf.back /etc/sysconfig/ha/conf/httpd.conf
