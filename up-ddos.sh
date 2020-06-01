#!/bin/bash

#########################################################
#                 ANTI-DDOS BASH SCRIPT                 #
#		   Created to mitigate DDOS/DOS attacks		    #
# 			Compatible with CS2D game servers			#
#########################################################
#                       CONTACT                         #
#########################################################
#              		DEVELOPER : Alex              		#
#			Discord : https://discord.gg/xYyM3zQ		#
#########################################################
#              		  VERSION 1.1              		    #
#			    Last Updated 30.05.2020		            #
#########################################################

IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
MODPROBE="/sbin/modprobe"
RMMOD="/sbin/rmmod"
ARP="/usr/sbin/arp"

##########################
#   VPS configuration    #
##########################

# VPS IP
SV_IP="34.89.152.11"

# Game server ports
SV_PORTS="--match multiport --dports 36964"

# SSH / FTP ports
OPEN_PORTS="--match multiport --dports 22"

# Whitelist static IP's
IP_WHITELIST="162.218.93.153"

# Whitelist dynamic IP's
IP_WHITELIST_DYNAMIC="-m iprange --src-range 162.218.93.0-162.218.93.255"

##########################
#        Spamhaus        #
##########################

# list of known spammers
SH_URL="www.spamhaus.org/drop/drop.lasso"

# save local copy here
SH_PATH="/tmp/drop.lasso"

# iptables custom chain
SH_CHAIN="Spamhaus"

##########################
#         Cleanup        #
##########################

# Delete all
$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -t mangle -F

# Delete all
$IPTABLES -X
$IPTABLES -t nat -X
$IPTABLES -t mangle -X

# Zero all packets and counters.
$IPTABLES -Z
$IPTABLES -t nat -Z
$IPTABLES -t mangle -Z

if test -x $IP6TABLES; then
    # Delete all rules.
    $IP6TABLES -F 2>/dev/null
    $IP6TABLES -t mangle -F 2>/dev/null

    # Delete all chains.
    $IP6TABLES -X 2>/dev/null
    $IP6TABLES -t mangle -X 2>/dev/null

    # Zero all packets and counters.
    $IP6TABLES -Z 2>/dev/null
    $IP6TABLES -t mangle -Z 2>/dev/null

    # Mangle table can pass everything
    $IP6TABLES -t mangle -P PREROUTING ACCEPT 2>/dev/null
    $IP6TABLES -t mangle -P INPUT ACCEPT 2>/dev/null
    $IP6TABLES -t mangle -P FORWARD ACCEPT 2>/dev/null
    $IP6TABLES -t mangle -P OUTPUT ACCEPT 2>/dev/null
    $IP6TABLES -t mangle -P POSTROUTING ACCEPT 2>/dev/null
fi

##########################
#         Kernel         #
##########################

# Load required kernel modules
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_conntrack_irc

# Configuration
#################################################################
# IPv4
#################################################################

# Disable IP forwarding.
# On => Off = (reset)
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_forward

# Enable IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

# Protect against SYN flood attacks
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Ignore all incoming ICMP echo requests
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore ICMP echo requests to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Log packets with impossible addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

# Don't log invalid responses to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Don't accept or send ICMP redirects.
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done

# Don't accept source routed packets.
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done

# Disable multicast routing
#for i in /proc/sys/net/ipv4/conf/*/mc_forwarding; do echo 0 > $i; done

# Disable proxy_arp.
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

# Enable secure redirects, i.e. only accept ICMP redirects for gateways
# Helps against MITM attacks.
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done

# Disable bootp_relay
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done

#################################################################
# IPv6
#################################################################

# Disable IPv6
#echo 0 > /proc/sys/net/ipv6/conf/*/disable_ipv6

# Disable Forwarding
#echo 0 > /proc/sys/net/ipv6/conf/*/forwarding

###########################
# Completely disable IPv6 #
###########################

# Block all IPv6 traffic
if test -x $IP6TABLES; then
    # Set the default policies
    $IP6TABLES -P INPUT DROP 2>/dev/null
    $IP6TABLES -P FORWARD DROP 2>/dev/null
    $IP6TABLES -P OUTPUT DROP 2>/dev/null
fi

##############################
# Custom user-defined chains #
##############################

# LOG packets, then DROP.
$IPTABLES -N DROPLOG
$IPTABLES -A DROPLOG -m limit --limit 1/s --limit-burst 2 -j LOG --log-prefix "[FIREWALL DROP] - " --log-level 6
$IPTABLES -A DROPLOG -j DROP

# LOG CS2D empty packets, then DROP.
$IPTABLES -N CS2DLOG
$IPTABLES -A CS2DLOG -m limit --limit 2/min -j LOG --log-prefix "[FIREWALL CS2D] - " --log-level 6
$IPTABLES -A CS2DLOG -j DROP

# Create Spamhaus chain or flush it if already exists
$IPTABLES -L $SH_CHAIN -n

if [ $? -eq 0 ]; then
    $IPTABLES -F $SH_CHAIN
    echo "Flushed old rules. Applying updated Spamhaus list...."    
else
    $IPTABLES -N $SH_CHAIN
    $IPTABLES -A INPUT -j $SH_CHAIN
    $IPTABLES -A FORWARD -j $SH_CHAIN
    echo "Chain not detected. Creating new chain and adding Spamhaus list...."
fi

####################
# BASIC PROTECTION #
####################

# Drop invalid packets
$IPTABLES -A INPUT -p udp $SV_PORTS -m state --state INVALID -j DROP
$IPTABLES -A OUTPUT -p udp $SV_PORTS -m state --state INVALID -j DROP
$IPTABLES -A FORWARD -p udp $SV_PORTS -m state --state INVALID -j DROP

# Drop spoofed packets from Spamhaus list
wget -qc $SH_URL -O $SH_PATH
    for IP in $( cat $SH_PATH | egrep -v '^;' | awk '{ print $1}' ); do
    #   $IPTABLES -A $SH_CHAIN -p 0 -s $IP -j LOG --log-prefix "[SPAMHAUS BLOCK]" -m limit --limit 3/min --limit-burst 10
        $IPTABLES -A INPUT -s $IP -j DROP
    #   echo $IP
    done
unlink $SH_PATH

# TOP 10, Block known-bad IPs (see http://www.dshield.org/top10.php)
$IPTABLES -A INPUT -s 185.217.0.156 -j DROP
$IPTABLES -A INPUT -s 193.142.146.88 -j DROP
$IPTABLES -A INPUT -s 185.40.4.128 -j DROP
$IPTABLES -A INPUT -s 89.248.168.226 -j DROP
$IPTABLES -A INPUT -s 2.207.135.70 -j DROP
$IPTABLES -A INPUT -s 141.98.83.11 -j DROP
$IPTABLES -A INPUT -s 185.202.2.147 -j DROP
$IPTABLES -A INPUT -s 185.176.222.39 -j DROP
$IPTABLES -A INPUT -s 141.98.9.30 -j DROP
$IPTABLES -A INPUT -s 185.209.0.71 -j DROP

# Drop any traffic from IANA-reserved IPs
$IPTABLES -A INPUT -s 0.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 2.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 5.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 7.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 10.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 23.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 27.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 31.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 36.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 39.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 42.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 49.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 50.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 77.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 78.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 92.0.0.0/6 -j DROP
$IPTABLES -A INPUT -s 96.0.0.0/4 -j DROP
$IPTABLES -A INPUT -s 112.0.0.0/5 -j DROP
$IPTABLES -A INPUT -s 120.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 169.254.0.0/16 -j DROP
$IPTABLES -A INPUT -s 172.16.0.0/12 -j DROP
$IPTABLES -A INPUT -s 173.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 174.0.0.0/7 -j DROP
$IPTABLES -A INPUT -s 176.0.0.0/5 -j DROP
$IPTABLES -A INPUT -s 184.0.0.0/6 -j DROP
$IPTABLES -A INPUT -s 192.0.2.0/24 -j DROP
$IPTABLES -A INPUT -s 197.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 198.18.0.0/15 -j DROP
$IPTABLES -A INPUT -s 223.0.0.0/8 -j DROP
$IPTABLES -A INPUT -s 224.0.0.0/3 -j DROP

#########################################
# Anti Dos & DDOs Protection & Exploits #
#########################################

# Drop NUL sized packets and log them
$IPTABLES -A INPUT -p udp $SV_PORTS -m length --length 0:28 -j CS2DLOG

# Drop abnormal sized packets
$IPTABLES -A INPUT -p udp $SV_PORTS -m length --length 1200:65535 -j DROP

# Drop Fragmented packets
$IPTABLES -A INPUT -f -j DROP

# UDP Flood through game server ports
$IPTABLES -N UDP_FLOODLOG
$IPTABLES -A INPUT -p udp $SV_PORTS -j UDP_FLOODLOG
$IPTABLES -A UDP_FLOODLOG -m state --state NEW -m recent --update --seconds 1 --hitcount 10 -j RETURN
## $IPTABLES -A UDP_FLOODLOG -j LOG --log-level 4 --log-prefix '[FIREWALL UDP FLOOD] '
$IPTABLES -A UDP_FLOODLOG -j DROP

# Allow no more than 1 new connections per second
$IPTABLES -A INPUT -p udp $SV_PORTS -m connlimit --connlimit-above 1 -j DROP

#####################
# Allow connections #
#####################

# Server port
$IPTABLES -I INPUT -p udp $SV_PORTS -j ACCEPT

# Server IP
$IPTABLES -A INPUT -s $SV_IP -j ACCEPT

# Whitelist ourselves to access VPS, SSH and FTP
# Static IP's
$IPTABLES -I INPUT -p tcp -s $IP_WHITELIST $OPEN_PORTS -j ACCEPT
$IPTABLES -I OUTPUT -p tcp -s $IP_WHITELIST $OPEN_PORTS -j ACCEPT
$IPTABLES -I FORWARD -p tcp -s $IP_WHITELIST $OPEN_PORTS -j ACCEPT

# Dynamic IP's
$IPTABLES -I INPUT -p tcp $IP_WHITELIST_DYNAMIC $OPEN_PORTS -j ACCEPT
$IPTABLES -I OUTPUT -p tcp $IP_WHITELIST_DYNAMIC $OPEN_PORTS -j ACCEPT
$IPTABLES -I FORWARD -p tcp $IP_WHITELIST_DYNAMIC $OPEN_PORTS -j ACCEPT

###############################################
# Finnaly Drop all other incoming connections #
###############################################

$IPTABLES -A INPUT -j DROP

echo "firewall started"

exit 0
