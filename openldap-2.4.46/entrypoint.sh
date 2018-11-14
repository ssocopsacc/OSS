#!/bin/sh
./slapd -d 0 -f ./openldap_run_dep/slapd.conf -h "ldap:/// ldaps:///"
