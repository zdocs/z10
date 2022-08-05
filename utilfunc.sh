#!/bin/bash

updateSystemPackages() {
    echo "Updating system and installing some essential packages ..."
    #What are the other essential packages?
    DEBIAN_FRONTEND=noninteractive apt-get update -qq -y < /dev/null > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -qq -y < /dev/null > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y apt-utils< /dev/null > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y netcat-openbsd sudo libidn11 libpcre3 libgmp10 libexpat1 libstdc++6 perl libaio1 unzip pax sysstat sqlite3< /dev/null > /dev/null
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y dnsmasq lsb-release net-tools netfilter-persistent dnsutils iptables sed wget< /dev/null > /dev/null

    echo "Disabling some of the non-essential services for Zimbra ..."
    systemctl stop postfix
    systemctl disable postfix
    systemctl mask postfix

    systemctl stop iptables
    systemctl disable iptables
    systemctl mask iptables

    systemctl stop httpd
    systemctl disable httpd
    systemctl mask httpd

    systemctl stop exim
    systemctl disable exim
    systemctl mask exim

    systemctl stop named
    systemctl disable named
    systemctl mask named

    systemctl stop apache2
    systemctl disable apache2
    systemctl mask apache2

    systemctl stop sendmail
    systemctl disable sendmail
    systemctl mask sendmail

    systemctl stop mysqld
    systemctl disable mysqld
    systemctl mask mysqld

    systemctl stop mariadb
    systemctl disable mariadb
    systemctl mask mariadb

    systemctl stop systemd-resolved
    systemctl disable systemd-resolved
    systemctl mask systemd-resolved

    systemctl stop ufw
    systemctl disable ufw
    systemctl mask ufw    
}

fixFirewall() {
    # Update firewall
    echo "Enabling firewall for Zimbra ports ..."
    echo "Ports 22/25/143/80/443/995/993/9071 will be opened to the internet."
    echo "Please check your iptables for more info."

    #flushing iptables while having INPUT=DROP policy will terminate ssh connection
    iptables -P INPUT ACCEPT

    iptables --flush
    #block null packets
    iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP
    #block syn flood
    iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP
    #block XMAS packets
    iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

    #accept all traffic on your loopback interface
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT

    #Allow Established and Related Incoming Connections
    iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

    #Allow ports
    iptables -A INPUT -p tcp -m tcp --dport 143 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 993  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 995  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 443  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 9071  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 80  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 25  -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 389 -j ACCEPT
    iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

    #enable ping
    iptables -A INPUT -p icmp --icmp-type 8 -s 0/0 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -p icmp --icmp-type 0 -d 0/0 -m state --state ESTABLISHED,RELATED -j ACCEPT

    #Set policy defaults
    iptables -P OUTPUT ACCEPT
    iptables -P FORWARD ACCEPT
    iptables -P INPUT DROP

    #IPv6 closed for now
    /usr/sbin/ip6tables -P OUTPUT ACCEPT
    /usr/sbin/ip6tables -P FORWARD ACCEPT
    /usr/sbin/ip6tables -P INPUT DROP

    netfilter-persistent save
}

pingLicenseServer() {
    response=$(curl --write-out '%{http_code}' --silent --output /dev/null https://license.zimbra.com)
    if [[ "$response" == "200" ]]; then
       echo "Zimbra License server reachable ..."
       echo -e "${GREEN}... Done.${NC}"
    else
        echo -e "${RED} Issue with firewall ... Please check!${NC}"
        exit 1
    fi
}

installDNS() {
    #Install a DNSMASQ Server
    echo "Configuring dnsmasq ..."
    mv /etc/dnsmasq.conf /etc/dnsmasq.conf.old
    #create the conf file
    printf 'server=8.8.8.8\nserver=8.8.4.4\nserver=9.9.9.9\nserver=149.112.112.112\nserver=1.1.1.1\nserver=1.0.0.1\nlisten-address=127.0.0.1\ndomain='$DOMAIN'\nmx-host='$DOMAIN','$HOSTNAME',0\naddress=/'$HOSTNAME'/'$MYIP'\n' | tee -a /etc/dnsmasq.conf >/dev/null
    mv /etc/resolv.conf {,.old}
    echo "nameserver 127.0.0.1" > /etc/resolv.conf
    # restart dns services
    systemctl enable dnsmasq.service > /dev/null 2>&1 && systemctl restart dnsmasq.service
    echo -e "${GREEN}... Done.${NC}"

    # Check DNS
    echo "Checking DNS ..."
    name=`host license.zimbra.com`
    if [[ "$name" == *"not found"* ]]; then
        echo -e "${RED}DNS resolution failed! Check your resolve.conf file.${NC}"
        exit 1
    else
        echo -e "${GREEN}... Done.${NC}"
    fi
}

resetHostName() {
    # Reset the hosts file
    echo "Rewriting the /etc/hosts file ..."
    mv /etc/hosts /etc/hosts.old
    printf '127.0.0.1\tlocalhost.localdomain\tlocalhost\n127.0.1.1\tubuntu\n'$MYIP'\t'$HOSTNAME'\t${_arg_hostname:="mail"}\t' | tee -a /etc/hosts >/dev/null 2>&1
    echo -e "${GREEN}... Done.${NC}"
    echo "Setting hostname ($HOSTNAME) ..."
    hostnamectl set-hostname $HOSTNAME >/dev/null 2>&1
    echo -e "${GREEN}... Done.${NC}"
}

resetTimeDate() {
    echo "Setting timezone ($TIMEZONE) ..."
    timedatectl set-timezone $TIMEZONE >/dev/null 2>&1
    echo -e "${GREEN}... Done.${NC}"
}

configCert() {
    if [ "$LETSENCRYPT" != "${LETSENCRYPT#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
    if [ $(dig +short type257 $(hostname --d) | grep "letsencrypt.org" | grep -v "issuewild" | grep "issue" | wc -l) -eq 1 ]; then   
        echo "Installing certbot"
        apt install -y python3 python3-venv libaugeas0
        python3 -m venv /opt/certbot/
        /opt/certbot/bin/pip install --upgrade pip
        /opt/certbot/bin/pip install certbot
        ln -s /opt/certbot/bin/certbot /usr/local/sbin/certbot
        /usr/local/sbin/certbot certonly -d $(hostname --fqdn) --standalone --preferred-chain  "ISRG Root X1" --agree-tos --register-unsafely-without-email
        cat >> /usr/local/sbin/letsencrypt-zimbra << EOF
#!/bin/bash

/usr/local/sbin/certbot certonly -d $(hostname --fqdn) --standalone --manual-public-ip-logging-ok -n --preferred-chain  "ISRG Root X1" --agree-tos --register-unsafely-without-email

cp "/etc/letsencrypt/live/$(hostname --fqdn)/privkey.pem" /opt/zimbra/ssl/zimbra/commercial/commercial.key
chown zimbra:zimbra /opt/zimbra/ssl/zimbra/commercial/commercial.key
wget -O /tmp/ISRG-X1.pem https://letsencrypt.org/certs/isrgrootx1.pem.txt
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cp "/etc/letsencrypt/live/$(hostname --fqdn)/chain.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
cat /tmp/ISRG-X1.pem >> "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
chown zimbra:zimbra /etc/letsencrypt -R
cd /tmp
su - zimbra -c '/opt/zimbra/bin/zmcertmgr deploycrt comm "/etc/letsencrypt/live/$(hostname --fqdn)/cert.pem" "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"'
rm -f "/etc/letsencrypt/live/$(hostname --fqdn)/chainZimbra.pem"
EOF
        chmod +rx /usr/local/sbin/letsencrypt-zimbra
    else 
        echo "CAA record for your domain cannot be found, you should add it first, example for bind:"
        echo "@			CAA     0 issue \"letsencrypt.org\""
        exit 1
    fi
    fi
}

getLicense() {
    echo "Download the trial license ..."
    wget -q --no-check-certificate --no-proxy -O /tmp/zcs/ZCSLicense.xml "https://license.zimbra.com/zimbraLicensePortal/public/STLicense?IssuedToName=MyCompany&IssuedToEmail=noone@$DOMAIN" 
    if [ ! -s "/tmp/zcs/ZCSLicense.xml" ]; then
        echo -e "${RED}License file could not be downloaded. Please check and re-run $(basename $0).${NC}"
        exit 1
    fi
    echo -e "${GREEN}... Done.${NC}"
}


postInstallCert() {
    if [ "$LETSENCRYPT" != "${LETSENCRYPT#[Yy]}" ] ;then # this grammar (the #[] operator) means that the variable $answer where any Y or y in 1st position will be dropped if they exist.
        echo "Deploying Let's Encrypt on Zimbra"
        ln -s /usr/local/sbin/letsencrypt-zimbra /etc/cron.daily/letsencrypt-zimbra
        ip=$(dig +short @8.8.4.4 $(hostname))   # Ensure local IP resolution does not happen
        if [ -n "$ip" ]; then
            /etc/cron.daily/letsencrypt-zimbra
        else
            echo -e "${RED}Could not resolve hostname ...${NC}." 
            echo -e "${RED}Correct your nameserver entries and run the command ${GREEN}/etc/cron.daily/letsencrypt-zimbra${NC}."
        fi
    fi

}

postInstallZimbra() {
    echo "Deploying additional Zimlets"
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y zimbra-zimlet-user-sessions-management< /dev/null > /dev/null

    if [[ $(hostname --fqdn) == *"barrydegraaff"* ]] || [[ $(hostname --fqdn) == *"zimbra.tech"* ]]; then
    DEBIAN_FRONTEND=noninteractive apt-get install -qq -y zimbra-zimlet-sideloader< /dev/null > /dev/null
    fi

    echo "Setting optimal security settings"
    rm -Rf /tmp/provfile
    ZIMBRAIP=$(netstat -tulpn | grep slapd | awk '{print $4}' | awk -F ':' '{print $1}')

    cat >> /tmp/provfile << EOF
mcf zimbraPublicServiceProtocol https
mcf zimbraPublicServicePort 443
mcf zimbraPublicServiceHostname $HOSTNAME
mcf zimbraReverseProxySSLProtocols TLSv1.2
mcf +zimbraReverseProxySSLProtocols TLSv1.3
mcf zimbraReverseProxySSLCiphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384'

mcf +zimbraResponseHeader "Strict-Transport-Security: max-age=31536000; includeSubDomains"
mcf +zimbraResponseHeader "X-Content-Type-Options: nosniff"
mcf +zimbraResponseHeader "X-Robots-Tag: noindex"
mcf zimbraMailKeepOutWebCrawlers TRUE

mcf zimbraSSLDHParam /etc/ffdhe4096.pem

mcf zimbraMtaSmtpdTlsCiphers medium
mcf zimbraMtaSmtpdTlsMandatoryCiphers  medium
mcf zimbraMtaSmtpdTlsProtocols '>=TLSv1.2'
mcf zimbraMtaTlsSecurityLevel may

ms $HOSTNAME zimbraPop3CleartextLoginEnabled FALSE
ms $HOSTNAME zimbraImapCleartextLoginEnabled FALSE

mcf zimbraLastLogonTimestampFrequency 1s
mc default zimbraPrefShortEmailAddress FALSE

mcf +zimbraMailTrustedIP 127.0.0.1
mcf +zimbraMailTrustedIP $ZIMBRAIP
EOF

    sed -i 's/-server -Dhttps.protocols=TLSv1.2 -Djdk.tls.client.protocols=TLSv1.2/-server -Dhttps.protocols=TLSv1.2,TLSv1.3 -Djdk.tls.client.protocols=TLSv1.2,TLSv1.3/g' /opt/zimbra/conf/localconfig.xml
    wget https://raw.githubusercontent.com/internetstandards/dhe_groups/master/ffdhe4096.pem -O /etc/ffdhe4096.pem

    su - zimbra -c '/opt/zimbra/bin/postconf -e fast_flush_domains=""'
    su - zimbra -c '/opt/zimbra/bin/postconf -e smtpd_etrn_restrictions=reject'
    su - zimbra -c '/opt/zimbra/bin/postconf -e disable_vrfy_command=yes'
    su - zimbra -c '/opt/zimbra/bin/postconf -e tls_medium_cipherlist="ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"'
    su - zimbra -c '/opt/zimbra/bin/postconf -e tls_preempt_cipherlist=no'

    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsprotocolmin="3.3"'
    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_common_tlsciphersuite="HIGH"'
    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_supported=1'
    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e zimbra_require_interprocess_security=1'
    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e ldap_starttls_required=true'

    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e alias_login_enabled=false'
    su - zimbra -c '/opt/zimbra/bin/zmlocalconfig -e zimbra_same_site_cookie="Strict"'

    su - zimbra -c '/opt/zimbra/bin/zmprov < /tmp/provfile'

    #https://wiki.zimbra.com/wiki/Enabling_Admin_Console_Proxy
    su - zimbra -c "/opt/zimbra/libexec/zmproxyconfig -e -w -C -H $HOSTNAME"
}

miscConfig() {
    #other updates
    DEBIAN_FRONTEND=noninteractive apt install -y locales
    locale-gen "en_US.UTF-8"
    update-locale LC_ALL="en_US.UTF-8"
    apt-get -qq update
}

downloadBinaries() {
    #Download binaries
    echo "Downloading Zimbra 10 for Ubuntu $version ..."
    #if [[ "$version" == "20.04" ]]; then
    #    wget -O /tmp/zcs-NETWORK-9.1.0_BETA_4334.UBUNTU20_64.20220706123001.tgz 'ftp://91beta:Zimbra.9.1.Beta@ftp.zimbra.com/beta1/zcs-NETWORK-9.1.0_BETA_4334.UBUNTU20_64.20220706123001.tgz' > /dev/null 2>&1
    #elif [[ "$version" == "18.04" ]]; then
    #    wget -) /tmp/zcs-NETWORK-9.1.0_BETA_4334.UBUNTU18_64.20220706123001.tgz 'ftp://91beta:Zimbra.9.1.Beta@ftp.zimbra.com/beta1/zcs-NETWORK-9.1.0_BETA_4334.UBUNTU18_64.20220706123001.tgz' > /dev/null 2>&1
    #fi
    #echo -e "${GREEN}... Done.${NC}"
}

createConfig() {
    case $COMPONENT in
    allinone)
        sed -i 's|"$HOSTNAME"|"'${HOSTNAME}'"|g' "$mydir/10-All-in-One"
        sed -i 's|"admin@$DOMAIN"|"admin@'${DOMAIN}'"|g' "$mydir/10-All-in-One"
        sed -i 's|"$DOMAIN"|"'${DOMAIN}'"|g' "$mydir/10-All-in-One"
        sed -i 's|"$MYPASSWORD"|"'${MYPASSWORD}'"|g' "$mydir/10-All-in-One"
        sed -i 's|"$TIMEZONE"|"'${TIMEZONE}'"|g' "$mydir/10-All-in-One"
        memory=$(($(grep MemAvailable /proc/meminfo | awk '{print $2}')/1024/1024))
        sed -i 's|"$MEMORY"|"'${memory}'"|g' "$mydir/10-All-in-One"

        cat "$mydir/10-All-in-One" >/tmp/zcs/zconfig
        if [[ "$APACHE" == "y" ]]; then
            echo 'INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-snmp zimbra-store zimbra-apache zimbra-spell zimbra-convertd zimbra-memcached zimbra-proxy zimbra-onlyoffice"' >>/tmp/zcs/zconfig
        else 
            echo 'INSTALL_PACKAGES="zimbra-core zimbra-ldap zimbra-logger zimbra-mta zimbra-store zimbra-convertd zimbra-memcached zimbra-proxy zimbra-onlyoffice"' >>/tmp/zcs/zconfig
        fi
        cat <<EOF >/tmp/zcs/zkeys
    y
    y
    y
    y
    y
    n
    n
    y
    $APACHE
    $APACHE
    y
    y
    y
    y
    y
    y
    EOF
        ;;

    ldap)
        sed -i 's|"$HOSTNAME"|"'${HOSTNAME}'"|g' "$mydir/10-LDAP-Config"
        sed -i 's|"admin@$DOMAIN"|"admin@'${DOMAIN}'"|g' "$mydir/10-LDAP-Config"
        sed -i 's|"$DOMAIN"|"'${DOMAIN}'"|g' "$mydir/10-LDAP-Config"
        sed -i 's|"$MYPASSWORD"|"'${MYPASSWORD}'"|g' "$mydir/10-LDAP-Config"
        sed -i 's|"$TIMEZONE"|"'${TIMEZONE}'"|g' "$mydir/10-LDAP-Config"
        memory=$(($(grep MemAvailable /proc/meminfo | awk '{print $2}')/1024/1024))
        sed -i 's|"$MEMORY"|"'${memory}'"|g' "$mydir/10-LDAP-Config"
        cat "$mydir/10-LDAP-Config" >/tmp/zcs/zconfig
        cat "$mydir/10-LDAP-Answers" >/tmp/zcs/zkeys
        ;;

    mbs)
        sed -i 's|"$HOSTNAME"|"'${HOSTNAME}'"|g' "$mydir/10-MBS-Config"
        sed -i 's|"admin@$DOMAIN"|"admin@'${DOMAIN}'"|g' "$mydir/10-MBS-Config"
        sed -i 's|"$DOMAIN"|"'${DOMAIN}'"|g' "$mydir/10-MBS-Config"
        sed -i 's|"$MYPASSWORD"|"'${MYPASSWORD}'"|g' "$mydir/10-MBS-Config"
        sed -i 's|"$LDAPHOSTNAME"|"'${ldap}'"|g' "$mydir/10-MBS-Config"
        memory=$(($(grep MemAvailable /proc/meminfo | awk '{print $2}')/1024/1024))
        sed -i 's|"$MEMORY"|"'${memory}'"|g' "$mydir/10-MBS-Config"
        #LDAPSERVERID
        cat "$mydir/10-MBS-Config" >/tmp/zcs/zconfig
        cat "$mydir/10-MBS-Answers" >/tmp/zcs/zkeys
        ;;

    mtaproxy)
        cat "$mydir/10-MTAProxy-Config" >/tmp/zcs/zconfig
        cat "$mydir/10-MTAProxy-Answers" >/tmp/zcs/zkeys
        ;;

    *)
        echo -n "unknown value - check the component being installed!"
        echo ""
        exit 1
        ;;
    esac
}
