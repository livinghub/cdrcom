#This is a start cdrcom sh

#!/bin/bash
ACCOUNT='15115061038'
CODE='111111'
INET_NUM='eth0.2'
IP='192.168.195.126'
GW='192.168.195.254'
MAC='1c:b7:2c:a4:d0:f3'
DNS1='192.168.195.254'
DNS2='114.114.114.114'

ifconfig $INET_NUM $IP netmask 255.255.255.0
route add default gw $GW
ifconfig $INET_NUM hw ether $MAC
echo nameserver $DNS1 >> /etc/resolv.conf
echo nameserver $DNS2 >> /etc/resolv.conf
./dr $ACCOUNT $CODE $IP $MAC $INET_NUM &
