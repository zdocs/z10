# README

apt -y install git screen
screen
rm -rf z10
git clone https://github.com/zdocs/z10.git
cd z10 && chmod +x ./z10installer
./z10installer -p z1mbr4 -c ldap -t 'Asia/Kolkata' -l n zimbra91.com
#./z10installer -p z1mbr4 -c "mbs 10.0.0.215 ldap.zimbra91.com z1mbr4" -n mbs01 -t 'Asia/Kolkata' -l n zimbra91.com
#./z10installer -p z1mbr4 -c "mbs 10.0.0.215 ldap.zimbra91.com z1mbr4" -n mbs02 -t 'Asia/Kolkata' -l n zimbra91.com
#./z10installer -p z1mbr4 -c "mtaproxy 10.0.0.215 ldap.zimbra91.com z1mbr4" -n mail -t 'Asia/Kolkata' -l n zimbra91.com

#./z10installer -p z1mbr4 -c allinone -n mail -t 'Asia/Kolkata' -l n zimbra.shop