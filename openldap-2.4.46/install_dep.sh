#!/bin/sh 

install_rpms()
{
	for f in $(find slapd-binary-deplist/ -name "*.rpm"); 
	do 
		package_name=$(basename "$f" .rpm)
		rpm -q $package_name && echo skipping $package_name as already installed || rpm -ivh --nodeps $f 
	done 
}

install_additional_deps()
{
 for f in $(find additional-dep/ -name "*.rpm");
        do
                package_name=$(basename "$f" .rpm)
                rpm -q $package_name && echo skipping $package_name as already installed || rpm -ivh --nodeps $f
        done

}

build()
{
    #yum install -y libcurl && \
    cd openldap_source && \
    ./configure --enable-debug=yes --enable-cleartext=yes --enable-modules=yes --enable-ldap=yes --enable-rwm=yes && \
    make depend && \
    ( make || ./compile.sh ) && \
    mkdir -p /usr/local/etc/openldap && \
    cp -r ../openldap_run_dep/* /usr/local/etc/openldap &&
    cp ./servers/slapd/slapd ..    
}

clean()
{	[[ "$PWD" == *openldap_source ]] && cd ..
	rm -r ./openldap_source && echo ldap source is cleaned || return 0 
}

install_additional_deps && echo Installed Additional Deps && install_rpms && echo 'All the packages are installed' && yum -y update && echo yum update completed && build && echo build succeeded && clean && exit 0 || (echo failure.. aborting && exit 1)
