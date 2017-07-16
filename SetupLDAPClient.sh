#Set som variables first
logDir=~/log
serverAddress=ldap.10.10.10.1
domainPart1="cbs"
domainPart2="nl"

#Halt on any error
set -e

#Install needed packages
if [ ! -f "$logDir/step1" ]
then
yum update
yum install openldap-clients nss-pam-ldapd

touch $logDir/step1
fi

#Configure client authentication with authconfig
if [ ! -f "$logDir/step2" ]
then

authconfig --enableldap \
--enableldapauth \
--ldapserver=$serverAddress\
--ldapbasedn="dc=$domainPart1,dc=$domainPart2" \
--enablemkhomedir \
--update

authconfig --enablepamaccess --update

authconfig --test

touch $logDir/step2
fi

#Allow users to acces their profiles in SELinux
if [ ! -f "$logDir/step3" ]
then
cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' > mkhomedir.te
module mkhomedir 1.0;

require {
        type unconfined_t;
        type oddjob_mkhomedir_exec_t;
        class file entrypoint;
}

#============= unconfined_t ==============
allow unconfined_t oddjob_mkhomedir_exec_t:file entrypoint;
EOF

checkmodule -m -M -o mkhomedir.mod mkhomedir.te
semodule_package -o mkhomedir.pp -m mkhomedir.mod
semodule -i mkhomedir.pp

touch $logDir/step3
fi

if [ ! -f "$logDir/step4" ]
then
#Copy RootCA to CLIENT.
scṕ $serverAddress:/etc/pki/CA/certs/cacert.pem /etc/openldap/cacerts/cacert.pem

touch $logDir/step4
fi

if [ ! -f "$logDir/step5" ]
then
#Add the following lines to ldap.conf
cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' >/etc/openldap/ldap.conf
TLS_CACERTFILE /etc/openldap/cacerts/cacert.pem

# Turning this off breaks GSSAPI used with krb5 when rdns = false
SASL_NOCANON    on

TLS_REQCERT allow

URI ldaps://$serverAddress/
BASE dc=$domainPart1,dc=$domainPart2
EOF

touch $logDir/step5
fi

if [ ! -f "$logDir/step6" ]
then
#Update your client nslcd.conf as follows
cat << EOF | sed 's/^[ \t]*//' | sed 's/[ \t]*$//' >/etc/nslcd.conf
uri ldaps:/$serverAddress:636/
base dc=$domainPart1,dc=$domainPart2
tls_reqcert allow
tls_ciphers TLSv1
ssl on
tls_cacertdir /etc/openldap/cacerts
EOF

touch $logDir/step6
fi

if [ ! -f "$logDir/step7" ]
then
#enable PAM for SSH to use system-auth.
#Add the line on the very top on the auth section.
sed -e '0,/^auth/s//auth       include      system-auth\nauth/' /etc/pam.d/sshd > /etc/pam.d/sshd

touch $logDir/step7
fi

if [ ! -f "$logDir/step8" ]
then
#Restart client nslcd service
service nslcd restart

touch $logDir/step8
fi

if [ ! -f "$logDir/step9" ]
then
#Test whether client can connect to server
ldapsearch -v -H ldaps://ldap.hextrim.com/ -D cn=admins,dc=$domainPart1,dc=$domainPart2 -W
-x -b dc=$domainPart1,dc=$domainPart2 -d1
ldapsearch -H ldaps://$serverAddress:636 -D "cn=admins,dc=$domainPart1,dc=$domainPart2" -ZZ -d7

openssl s_client -connect $serverAddress:636 -showcerts

touch $logDir/step9
fi
