#Bash file based on tutorial:
#https://nfsec.co.uk/openldap-on-centos7-with-tls-ssl-rootca-and-client-in-selinux-mode/

#TODO: overwrite config file in every cat command
#Halt on any error
set -e

#Set some variables to be used first
logDir=~/log
domainPart1="cbs"
domainPart2="nl"
countryName="NL"
state="Limburg"
locality="Heerlen"
organizationName="CBS"
organizationUnit="CBDS"
commonName="megatron"
opensslSubject="/C=$countryName/ST=$state/L=$locality/O=$organizationName/OU=$organizationUnit/CN=$commonName"


if [ ! -f "$logDir/step1" ]
then

	mkdir $logDir

	#set -x

	#OpenSSL configuration
	cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.ORIG

	#Without P
	#Write a config file fthenor you own eleet CA
	cp ./openssl.cnf /etc/pki/tls/openssl.cnf

	#Create index.txt file as a DB about the issues and revoked certs
	cd /etc/pki/CA/
	touch index.txt
	printf '01' > serial.txt

	#Use your CA config file to actually create a trusted CA valid for 10 years!
	#With Password
	openssl req -config /etc/pki/tls/openssl.cnf -new -x509 -extensions v3_ca -keyout private/cakey.pem -out certs/cacert.pem -subj $opensslSubject -days 3650

	touch $logDir/step1

fi

if [ ! -f "$logDir/step2" ]
then
	#Without Password - using no password in this article
	openssl req -config /etc/pki/tls/openssl.cnf -new -x509 -extensions v3_ca -keyout private/cakey.pem -out certs/cacert.pem -subj $opensslSubject -nodes -days 3650

	touch $logDir/step2
fi


if [ ! -f "$logDir/step3" ]
then
	#Give key file read-only permission
	chmod 0400 private/cakey.pem

	#Verify Your new CA, to see how long is valid for and that.
	openssl x509 -in certs/cacert.pem -text -noout
	touch $logDir/step3
fi

if [ ! -f "$logDir/step4" ]
then

	#Create an CSR for your OpenLDAP server.
	openssl req -config /etc/pki/tls/openssl.cnf -newkey rsa:2048 -sha256 -nodes -out ldapcert.csr -subj $opensslSubject -outform PEM -keyout ldapkey.pem
	touch $logDir/step4
fi


if [ ! -f "$logDir/step5" ]
then
	#Sign CSR with new CA
	openssl ca -config /etc/pki/tls/openssl.cnf -policy signing_policy -extensions signing_req -out ldapcert.pem -infiles ldapcert.csr

	#Verify Your new CA
	openssl x509 -in ldapcert.pem -text -noout

	touch $logDir/step5
fi

if [ ! -f "$logDir/step6" ]
then
	# Install OpenLDAP Server
	yum -y update
	yum -y install epel-release
	yum -y install openldap-clients openldap-servers

	touch $logDir/step6
fi

if [ ! -f "$logDir/step7" ]
then
	getenforce

	setsebool -P allow_ypbind=0 authlogin_nsswitch_use_ldap=0

	touch $logDir/step7
fi

if [ ! -f "$logDir/step8" ]
then
	systemctl enable slapd.service
	systemctl start slapd.service


	touch $logDir/step8
fi

if [ ! -f "$logDir/step9" ]
then
	cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

	chown -R ldap:ldap /var/lib/ldap/


	touch $logDir/step9
fi

if [ ! -f "$logDir/step11" ]
then
	#Generate sha512 hash for your master LDAP account as shown below.
	cd /etc/openldap/slapd.d/

	masterHash=$(slappasswd)
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > ldaprootpasswd.ldif
dn: olcDatabase={0}config,cn=config
changetype: modify
add: olcRootPW
olcRootPW: $masterHash
EOF
	#Update LDAP Directory services
	ldapadd -H ldapi:/// -f ldaprootpasswd.ldif

	touch $logDir/step11
fi

if [ ! -f "$logDir/step12" ]
then
	#Import basic schemas.
	for def in cosine.ldif nis.ldif inetorgperson.ldif; do ldapadd -H ldapi:/// -f /etc/openldap/schema/$def; done

	touch $logDir/step12
fi

if [ ! -f "$logDir/step13" ]
then
	#Create your own domain, RootDN, access policy
	cat << EOF | sed 's/[ \t]*$//' > ldapdomain.ldif
dn: olcDatabase={1}monitor,cn=config
changetype: modify
replace: olcAccess
olcAccess: {0}to * by dn.base="gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth"
  read by dn.base="cn=admins,dc=$domainPart1,dc=$domainPart2" read by * none

dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcSuffix
olcSuffix: dc=$domainPart1,dc=$domainPart2

dn: olcDatabase={2}hdb,cn=config
changetype: modify
replace: olcRootDN
olcRootDN: cn=admins,dc=$domainPart1,dc=$domainPart2

dn: olcDatabase={2}hdb,cn=config
changetype: modify
add: olcRootPW
olcRootPW: $masterHash

dn: olcDatabase={2}hdb,cn=config
changetype: modify
add: olcAccess
olcAccess: {0}to attrs=userPassword,shadowLastChange
  by dn="cn=admins,dc=$domainPart1,dc=$domainPart2"
  write by anonymous auth by self write by * none
olcAccess: {1}to dn.base="" by * read
olcAccess: {2}to * by dn="cn=admins,dc=$domainPart1,dc=$domainPart2" write by * read
EOF
	#Import it
	ldapmodify -H ldapi:/// -f ldapdomain.ldif

	touch $logDir/step13
fi

if [ ! -f "$logDir/step15" ]
then
	#Create base domain
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > baseldapdomain.ldif
dn: dc=$domainPart1,dc=$domainPart2
objectClass: top
objectClass: dcObject
objectclass: organization
o: $organizationName
dc: $domainPart1

dn: cn=admins,dc=$domainPart1,dc=$domainPart2
objectClass: organizationalRole
cn: admins
description: Directory Admins

dn: ou=users,dc=$domainPart1,dc=$domainPart2
objectClass: organizationalUnit
ou: users

dn: ou=group,dc=$domainPart1,dc=$domainPart2
objectClass: organizationalUnit
ou: group"
EOF
	#Import $it
	ldapadd -x -D cn=admins,dc=$domainPart1,dc=$domainPart2 -W -f baseldapdomain.ldif

	touch $logDir/step15
fi

if [ ! -f "$logDir/step16" ]
then
	#Enable LDAPS - the TLS/SSL version
	cp /etc/pki/CA/certs/cacert.pem /etc/openldap/certs/
	cp /etc/pki/CA/ldapkey.pem /etc/openldap/certs/
	cp /etc/pki/CA/ldapcert.pem /etc/openldap/certs/

	chown -R ldap:ldap /etc/openldap/certs/*.pem

	touch $logDir/step16
fi

if [ ! -f "$logDir/step17" ]
then
	#Point the LDAP Attributes regarding TLS/SSL certificate location
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > cbdscerts.ldif
dn: cn=config
changetype: modify
replace: olcTLSCACertificateFile
olcTLSCACertificateFile: /etc/openldap/certs/cacert.pem
-
replace: olcTLSCertificateFile
olcTLSCertificateFile: /etc/openldap/certs/ldapcert.pem
-
replace: olcTLSCertificateKeyFile
olcTLSCertificateKeyFile: /etc/openldap/certs/ldapkey.pem"
-
add: olcTLSProtocolMin
olcTLSProtocolMin: 3.2
-
add: olcTLSCipherSuite
olcTLSCipherSuite: EECDH:EDH:CAMELLIA:ECDH:RSA:!eNULL:!SSLv2:!RC4:!DES:!EXP:!SEED:!IDEA:!3DES
EOF
	#Import it
	ldapmodify -Y EXTERNAL  -H ldapi:/// -f cbdscerts.ldif

	touch $logDir/step17
fi

if [ ! -f "$logDir/step21" ]
then
	#Point the LDAP Server to the certs in slapd.conf
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > /etc/openldap/slapd.conf
TLSCACertificateFile /etc/openldap/certs/cacert.pem
TLSCertificateFile /etc/openldap/certs/ldapcert.pem
TLSCertificateKeyFile /etc/openldap/certs/ldapkey.pem
EOF

	touch $logDir/step21
fi

if [ ! -f "$logDir/step22" ]
then
	#Only use ldapi and ldaps protocols for communication with clients
	printf 'SLAPD_URLS="ldapi:/// ldap:/// ldaps:///"

	SLAPD_LDAP=no
	SLAPD_LDAPI=no
	SLAPD_LDAPS=yes' > /etc/sysconfig/slapd

	touch $logDir/step22
fi

if [ ! -f "$logDir/step23" ]
then
	#Test our configuration file
	slaptest -f /etc/openldap/slapd.conf

	#Restart slapd service and display status
	systemctl restart slapd
	systemctl status slapd

	touch $logDir/step23
fi

if [ ! -f "$logDir/step24" ]
then
	#Create our master admin account
	slaptest -u

	cat /etc/passwd

	adduser admin

	touch $logDir/step24
fi

if [ ! -f "$logDir/step25" ]
then
	#Create sha512 for our new admin
	adminHash=$(slappasswd)

	#Create admin user specific policy
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > admin.ldif
dn: uid=admin,ou=users,dc=$domainPart1,dc=$domainPart2
objectClass: top
objectClass: account
objectClass: posixAccount
objectClass: shadowAccount
cn: admin
uid: admin
uidNumber: 1000
gidNumber: 1000
homeDirectory: /home/admin
userPassword: $adminHash
loginShell: /bin/bash
gecos: admin
shadowLastChange: 0
shadowMax: -1
shadowWarning: 0
EOF
	#Add user
	ldapadd -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -f admin.ldif

	touch $logDir/step25
fi

if [ ! -f "$logDir/step26" ]
then
	#Make user member of OU "group"
	cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > admingroup.ldif
dn: cn=admins,ou=group,dc=$domainPart1,dc=$domainPart2
objectClass: top
objectClass: posixGroup
gidNumber: 1000
EOF
	#Group import
	ldapadd -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -f admingroup.ldif

	touch $logDir/step26
fi

if [ ! -f "$logDir/step27" ]
then
	#Verify that user uid=admin exists on server
	ldapsearch -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -b "uid=admin,ou=users,dc=$domainPart1,dc=$domainPart2" "(objectclass=*)"

	#Verify if ldap:// still works locally and if ldaps:// even works?
#	ldapsearch -H ldap://ldap.$domainPart1.$domainPart2 -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -w -ZZ -d7
#	ldapsearch -H ldaps://ldap.$domainPart1.$domainPart2:636 -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -w -ZZ -d7

	#Check what TLS attributes are set on your LDAP Directory.
	ldapsearch -LLL -Y EXTERNAL -H ldapi:/// -b cn=config|grep TLS

	#Config SE Linux to allow connect to ldap via http
	setsebool -P httpd_can_connect_ldap on

	touch $logDir/step27
fi


if [ ! -f "$logDir/step28" ]
then
    #"firewall-cmd --add-service=ldaps --permanent
    firewall-cmd --add-service=ldap  --permanent
    firewall-cmd --reload

    touch $logDir/step28
fi
