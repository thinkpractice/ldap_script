	#Bash file based on tutorial:
#https://nfsec.co.uk/openldap-on-centos7-with-tls-ssl-rootca-and-client-in-selinux-mode/

#Halt on any error
set -e

#Set some variables to be used first
domainPart1="cbs"
domainPart2="nl"


#OpenSSL configuration
cp /etc/pki/tls/openssl.cnf /etc/pki/tls/openssl.cnf.ORIG

#Write a config file for you own eleet CA
cp ./openssl.cnf /etc/pki/tls/openssl.cnf

#Create index.txt file as a DB about the issues and revoked certs
cd /etc/pki/CA/  
touch index.txt  
echo '01' > serial.txt 

#Use your CA config file to actually create a trusted CA valid for 10 years!
#With Password  
#openssl req -config /etc/pki/tls/openssl.cnf -new -x509 -extensions v3_ca -keyout private/cakey.pem -out certs/cacert.pem -days 3650

#Without Password - using no password in this article  
	openssl req -config /etc/pki/tls/openssl.cnf -new -x509 -extensions v3_ca -keyout private/cakey.pem -out certs/cacert.pem -nodes -days 3650

#Give key file read-only permission
chmod 0400 private/cakey.pem 

#Verify Your new CA, to see how long is valid for and that.
openssl x509 -in certs/cacert.pem -text -noout

#Create an CSR for your OpenLDAP server. 
openssl req -config /etc/pki/tls/openssl.cnf -newkey rsa:2048 -sha256 -nodes -out ldapcert.csr -outform PEM -keyout ldapkey.pem

#Sign CSR with new CA

openssl req -config /etc/pki/tls/openssl.cnf -newkey rsa:2048 -sha256 -nodes -out ldapcert.csr -outform PEM -keyout ldapkey.pem

#Verify Your new CA 
openssl x509 -in ldapkey.pem -text -noout

# Install OpenLDAP Server
yum update  
yum -y install epel-release  
yum -y install openldap-clients openldap-servers

getenforce

setsebool -P allow_ypbind=0 authlogin_nsswitch_use_ldap=0

systemctl enable slapd.service  
systemctl start slapd.service

cp /usr/share/openldap-servers/DB_CONFIG.example /var/lib/ldap/DB_CONFIG

chown -R ldap:ldap /var/lib/ldap/

#Generate sha512 hash for your master LDAP account as shown below.
cd /etc/openldap/sldap.d/

masterHash=$(slappasswd)
 
echo "dn: olcDatabase={0}config,cn=config  
changetype: modify  
add: olcRootPW  
olcRootPW: $masterHash  
" > ldaprootpasswd.ldif

#Update LDAP Directory services
ldapadd -H ldapi:/// -f ldaprootpasswd.ldif

#Import basic schemas.
for def in cosine.ldif nis.ldif inetorgperson.ldif; do ldapadd -H ldapi:/// -f /etc/openldap/schema/$def; done

#Create your own domain, RootDN, access policy
echo "dn: olcDatabase={1}monitor,cn=config  
changetype: modify  
replace: olcAccess  
olcAccess: {0}to * by dn.base=\"gidNumber=0+uidNumber=0,cn=peercred,cn=external,cn=auth\" read by dn.base=\"cn=admins,dc=$domainPart1,dc=$domainPart2\" 

read by * none

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
olcAccess: {0}to attrs=userPassword,shadowLastChange by dn=\"cn=admins,dc=$domainPart1,dc=$domainPart2\" write by anonymous auth by self write by * none  
olcAccess: {1}to dn.base=\"\" by * read  
olcAccess: {2}to * by dn=\"cn=admins,dc=$domainPart1,dc=$domainPart2\" write by * read " > ldapdomain.ldif

#Import it
ldapmodify -H ldapi:/// -f ldapdomain.ldif

#Create base domain
echo "dn: dc=$domainPart1,dc=$domainPart2  
objectClass: top  
objectClass: dcObject  
objectclass: organization  
o: CBS  
dc: $domainPart1

dn: cn=admins,dc=$domainPart1,dc=$domainPart2  
objectClass: organizationalRole  
cn: admins  
description: Directory Admins

dn: ou=users,dc=$domainPart1,dc=$domainPart2  
objectClass: organizationalUnit  
ou: users

dn: ou=groupd,dc=$domainPart1,dc=$domainPart2
objectClass: organizationalUnit  
ou: group" >  baseldapdomain.ldif 

#Import it
ldapadd -x -D cn=admins,dc=$domainPart1,dc=$domainPart2 -W -f baseldapdomain.ldif

#Enable LDAPS - the TLS/SSL version 
cp /etc/pki/CA/certs/cacert.pem /etc/openldap/certs/  
cp /etc/pki/CA/ldapkey.pem /etc/openldap/certs/  
cp /etc/pki/CA/ldapcert.pem /etc/openldap/certs/

chown -R ldap:ldap /etc/openldap/certs/*.pem

#Point the LDAP Attributes regarding TLS/SSL certificate location
echo "dn: cn=config  
changetype: modify  
replace: olcTLSCACertificateFile  
olcTLSCACertificateFile: /etc/openldap/certs/cacert.pem  
-
replace: olcTLSCertificateFile  
olcTLSCertificateFile: /etc/openldap/certs/ldapcert.pem  
-
replace: olcTLSCertificateKeyFile  
olcTLSCertificateKeyFile: /etc/openldap/certs/ldapkey.pem"
> cbdscerts.ldif

#Import it
ldapmodify -Y EXTERNAL  -H ldapi:/// -f cbdscerts.ldif  

#Use the most secured ciphers available for our secured communication!
echo "dn: cn=config  
changetype: modify  
replace: olcTLSCipherSuite

oldTLSCipherSuite: EECDH:EDH:CAMELLIA:ECDH:RSA:!eNULL:!SSLv2:!RC4:!DES:!EXP:!SEED:!IDEA:!3DES

add: olcTLSProtocolMin  
olcTLSProtocolMin: 3.2" > cipher.ldif

#Import it
ldapmodify -Y EXTERNAL -H ldapi:/// -f cipher.ldif

#Point the LDAP Server to the certs in slapd.conf 
echo 'TLSCACertificateFile /etc/openldap/certs/cacert.pem  
TLSCertificateFile /etc/openldap/certs/ldapcert.pem  
TLSCertificateKeyFile /etc/openldap/certs/ldapkey.pem ' > /etc/openldap/slapd.conf

#Only use ldapi and ldaps protocols for communication with clients  
echo 'SLAPD_URLS="ldapi:/// ldaps:///"

SLAPD_LDAP=no  
SLAPD_LDAPI=no  
SLAPD_LDAPS=yes' > /etc/sysconfig/slaṕd 

#Test our configuration file
slaptest -f /etc/openldap/slapd.conf

#Restart slapd service and display status
systemctl restart slapd  
systemctl status slapd

#Create our master admin account
slaptest -u

cat /etc/passwd

adduser admin

#Create sha512 for our new admin
adminHash=$(slappasswd) 

#Create admin user specific policy
echo "dn: uid=admin,ou=users,dc=hextrim,dc=com  
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
shadowMax: -1 ####### If you leave this 0 you will end up with constant password change requests  
shadowWarning: 0" > admin.ldif

#Add user
ldapadd -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -f admin.ldif

#Make user member of OU "group"
echo "dn: cn=admins,ou=group,dc=$domainPart1,dc=$domainPart2  
objectClass: top  
objectClass: posixGroup  
gidNumber: 1000" > admingroup.ldif 

#Group import
ldapadd -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -f admingroup.ldif  

#Verify that user uid=admin exists on server
ldapsearch -x -W -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -b "uid=admin,ou=users,dc=$domainPart1,dc=$domainPart2" "(objectclass=*)"

#Verify if ldap:// still works locally and if ldaps:// even works?
ldapsearch -H ldap://ldap.$domainPart1.$domainPart2 -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -w -ZZ -d7  
ldapsearch -H ldaps://ldap.$domainPart1.$domainPart2:636 -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -w -ZZ -d7  

#Check what TLS attributes are set on your LDAP Directory. 
ldapsearch -LLL -Y EXTERNAL -H ldapi:/// -b cn=config|grep TLS  

#Config SE Linux to allow connect to ldap via http
setsebool -P httpd_can_connect_ldap on 

