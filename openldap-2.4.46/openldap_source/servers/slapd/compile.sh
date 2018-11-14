#!/bin/bash

cc -g -fPIC -pthread -D_GNU_SOURCE -I/usr/include/libxml2 -c -o otpc.o otpc.c
cc -g -O2 -o slapd main.o globals.o bconfig.o config.o daemon.o connection.o search.o filter.o add.o cr.o attr.o entry.o backend.o backends.o result.o operation.o dn.o compare.o modify.o delete.o modrdn.o ch_malloc.o value.o ava.o bind.o unbind.o abandon.o filterentry.o phonetic.o acl.o str2filter.o aclparse.o init.o user.o lock.o controls.o extended.o passwd.o schema.o schema_check.o schema_init.o schema_prep.o schemaparse.o ad.o at.o mr.o syntax.o oc.o saslauthz.o oidm.o starttls.o index.o sets.o referral.o root_dse.o sasl.o module.o mra.o mods.o sl_malloc.o zn_malloc.o limits.o operational.o matchedValues.o cancel.o syncrepl.o backglue.o backover.o ctxcsn.o ldapsync.o frontend.o slapadd.o slapcat.o slapcommon.o slapdn.o slapindex.o slappasswd.o slaptest.o slapauth.o slapacl.o component.o aci.o alock.o txn.o slapschema.o version.o otpc.o -pthread -Wl,--export-dynamic  libbackends.a liboverlays.a ../../libraries/liblunicode/liblunicode.a ../../libraries/librewrite/librewrite.a ../../libraries/liblutil/liblutil.a ../../libraries/libldap_r/.libs/libldap_r.a /root/sslvpnsource/openldap-2.4.46/openldap_source/libraries/liblber/.libs/liblber.a ../../libraries/liblber/.libs/liblber.a -lltdl -ldb-5.3 -licuuc -licudata -lsasl2 -lssl -lcrypto -lresolv -pthread -lxml2 -lcurl

if [ $? -eq 0 ]
then
	exit 0
else
	exit 1
fi
