#!/bin/sh

#########################################################
#                 ANTI-DDOS BASH SCRIPT                 #
#			Created to mitigate DDOS/DOS attacks		#
# 			 Compatible with CS2D game servers			#
#########################################################
#                       CONTACT                         #
#########################################################
#              		DEVELOPER : Alex              		#
#			Discord : https://discord.gg/xYyM3zQ		#
#########################################################

# For debugging use iptables -v.
IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
MODPROBE="/sbin/modprobe"
RMMOD="/sbin/rmmod"
ARP="/usr/sbin/arp"

# Logging options.
#------------------------------------------------------------------------------
LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
LOG="$LOG --log-ip-options"

# Defaults for rate limiting
#------------------------------------------------------------------------------
RLIMIT="-m limit --limit 1/s --limit-burst 2"

# Unprivileged ports.
#------------------------------------------------------------------------------
PHIGH="1024:65535"
PSSH="1000:1023"

# Load required kernel modules
#------------------------------------------------------------------------------
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_conntrack_irc

# Mitigate ARP spoofing/poisoning and similar attacks.
#------------------------------------------------------------------------------
# Hardcode static ARP cache entries here
# $ARP -s IP-ADDRESS MAC-ADDRESS

# Kernel configuration.
#------------------------------------------------------------------------------

#################################################################
# IPv4
#################################################################

# Disable IP forwarding.
# On => Off = (reset)
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 0 > /proc/sys/net/ipv4/ip_forward

# Enable enable_sack
echo 1 > /proc/sys/net/ipv4/tcp_sack
echo 1 > /proc/sys/net/ipv4/tcp_dsack
echo 1 > /proc/sys/net/ipv4/tcp_fack

# Enable IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

# Protect against SYN flood attacks
echo 1 > /proc/sys/net/ipv4/tcp_syncookies
echo 2048 > /proc/sys/net/ipv4/tcp_max_syn_backlog
echo 5 > /proc/sys/net/ipv4/tcp_syn_retries
echo 5 > /proc/sys/net/ipv4/tcp_synack_retries

# Ignore all incoming ICMP echo requests
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore ICMP echo requests to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Don't log invalid responses to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Log packets with impossible source addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

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

# Default policies.
#------------------------------------------------------------------------------

# Drop everything by default.
$IPTABLES -P INPUT DROP
$IPTABLES -P FORWARD DROP
$IPTABLES -P OUTPUT DROP

# Set the nat/mangle/raw tables' chains to ACCEPT
$IPTABLES -t nat -P PREROUTING ACCEPT
$IPTABLES -t nat -P OUTPUT ACCEPT
$IPTABLES -t nat -P POSTROUTING ACCEPT

$IPTABLES -t mangle -P PREROUTING ACCEPT
$IPTABLES -t mangle -P INPUT ACCEPT
$IPTABLES -t mangle -P FORWARD ACCEPT
$IPTABLES -t mangle -P OUTPUT ACCEPT
$IPTABLES -t mangle -P POSTROUTING ACCEPT

# Cleanup.
#------------------------------------------------------------------------------

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

# Completely disable IPv6.
#------------------------------------------------------------------------------

# Block all IPv6 traffic
# If the ip6tables command is available, try to block all IPv6 traffic.
if test -x $IP6TABLES; then
# Set the default policies
# drop everything
$IP6TABLES -P INPUT DROP 2>/dev/null
$IP6TABLES -P FORWARD DROP 2>/dev/null
$IP6TABLES -P OUTPUT DROP 2>/dev/null

# The mangle table can pass everything
$IP6TABLES -t mangle -P PREROUTING ACCEPT 2>/dev/null
$IP6TABLES -t mangle -P INPUT ACCEPT 2>/dev/null
$IP6TABLES -t mangle -P FORWARD ACCEPT 2>/dev/null
$IP6TABLES -t mangle -P OUTPUT ACCEPT 2>/dev/null
$IP6TABLES -t mangle -P POSTROUTING ACCEPT 2>/dev/null

# Delete all rules.
$IP6TABLES -F 2>/dev/null
$IP6TABLES -t mangle -F 2>/dev/null

# Delete all chains.
$IP6TABLES -X 2>/dev/null
$IP6TABLES -t mangle -X 2>/dev/null

# Zero all packets and counters.
$IP6TABLES -Z 2>/dev/null
$IP6TABLES -t mangle -Z 2>/dev/null
fi

# Custom user-defined chains.
#------------------------------------------------------------------------------

# LOG packets, then ACCEPT.
$IPTABLES -N ACCEPTLOG
$IPTABLES -A ACCEPTLOG -j $LOG $RLIMIT --log-prefix "ACCEPT "
$IPTABLES -A ACCEPTLOG -j ACCEPT

# LOG packets, then DROP.
$IPTABLES -N DROPLOG
$IPTABLES -A DROPLOG -j $LOG $RLIMIT --log-prefix "DROP "
$IPTABLES -A DROPLOG -j DROP

# LOG packets, then REJECT.
# TCP packets are rejected with a TCP reset.
$IPTABLES -N REJECTLOG
$IPTABLES -A REJECTLOG -j $LOG $RLIMIT --log-prefix "REJECT "
$IPTABLES -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
$IPTABLES -A REJECTLOG -j REJECT

# Only allows RELATED ICMP types
$IPTABLES -N RELATED_ICMP
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type time-exceeded -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type parameter-problem -j ACCEPT
$IPTABLES -A RELATED_ICMP -j DROPLOG

# Make It Even Harder To Multi-PING
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j LOG --log-prefix PING-DROP:
$IPTABLES  -A INPUT -p icmp -j DROP
$IPTABLES  -A OUTPUT -p icmp -j ACCEPT

# Prevent DDOS attack: Ping of Death
$IPTABLES -N PING_OF_DEATH
$IPTABLES -A PING_OF_DEATH -p icmp --icmp-type echo-request \
-m hashlimit \
--hashlimit 10/s \
--hashlimit-burst 10 \
--hashlimit-htable-expire 300000 \
--hashlimit-mode srcip \
--hashlimit-name t_PING_OF_DEATH \
-j RETURN
$IPTABLES -A PING_OF_DEATH -j DROP
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j PING_OF_DEATH

# Only allow the minimally required/recommended parts of ICMP. Block the rest.
#------------------------------------------------------------------------------

# First, drop all fragmented ICMP packets (almost always malicious).
$IPTABLES -A INPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A OUTPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A FORWARD -p icmp --fragment -j DROPLOG

# Allow all ESTABLISHED ICMP traffic.
$IPTABLES -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT

# Allow some parts of the RELATED ICMP traffic, block the rest.
$IPTABLES -A INPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT

# Allow incoming ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT

# Allow outgoing ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT

# Drop any other ICMP traffic.
$IPTABLES -A INPUT -p icmp -j DROPLOG
$IPTABLES -A OUTPUT -p icmp -j DROPLOG
$IPTABLES -A FORWARD -p icmp -j DROPLOG

# Selectively allow certain special types of traffic.
#------------------------------------------------------------------------------

# Allow loopback interface to do anything.
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Allow incoming connections related to existing allowed connections.
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -m tcp -p tcp --dport 22 -j ACCEPT

# Allow outgoing connections EXCEPT invalid
$IPTABLES -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

# Miscellaneous.
#------------------------------------------------------------------------------

# Limit the amount of NEW connections
# to a maximum of $CONNECTIONS per $SECONDS per remote-ip
# this is usefull, if someone tries to DOS or synflood your box
# and helps to prevent dictonary-attacks
$IPTABLES -A INPUT -p tcp -m state --state NEW -m recent --set
$IPTABLES -A INPUT -p tcp -m state --state NEW -m recent --update --seconds 60 --hitcount 120 -j DROP

$IPTABLES -A INPUT -p udp -m state --state NEW -m recent --set
$IPTABLES -A INPUT -p udp -m state --state NEW -m recent --update --seconds 1 --hitcount 2 -j DROP

# We don't care about Milkosoft, Drop SMB/CIFS/etc..
$IPTABLES -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
$IPTABLES -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP

# Explicitly drop invalid incoming traffic
$IPTABLES -A INPUT -m state --state INVALID -j DROP

# Drop invalid outgoing traffic, too.
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP

# If we would use NAT, INVALID packets would pass - BLOCK them anyways
$IPTABLES -A FORWARD -m state --state INVALID -j DROP

# PORT Scanners (stealth also)
## ALL
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
## nmap Null scans / no flags
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP
## nmap FIN stealth scan
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL FIN -j DROP
## SYN + FIN
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
## SYN + RST
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
## FIN + RST
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
## FIN + URG + PSH
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
## XMAS
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL URG,ACK,PSH,RST,SYN,FIN -j DROP
## FIN/PSH/URG without ACK
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ACK,URG URG -j DROP

# Drop excessive RST packets to avoid smurf attacks
$IPTABLES -A INPUT -p tcp -m tcp --tcp-flags RST RST -m limit --limit 2/second --limit-burst 2 -j ACCEPT

# Drop excessive UDP packets
$IPTABLES -A INPUT -p udp -m limit --limit 1/sec --limit-burst 2 -j RETURN
$IPTABLES -A FORWARD -p udp -m limit --limit 1/s -j ACCEPT

# TODO: Some more anti-spoofing rules? For example:
# $IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
# $IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# $IPTABLES -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -N SYN_FLOOD
$IPTABLES -A INPUT -p tcp --syn -j SYN_FLOOD
$IPTABLES -A SYN_FLOOD -m limit --limit 1/s --limit-burst 2 -j RETURN
$IPTABLES -A SYN_FLOOD -j DROP

#------------------------------------------------------------------------------
# CS2D, including its exploits
#------------------------------------------------------------------------------

# Drop packets under 0 and 28 bytes (cs2d)
$IPTABLES -A INPUT -p udp --dport 10010 -m length --length 0:28 -j REJECT

# Drop packets under 1200 and 65535 bytes of data (cs2d will never use more
# than 1200 bytes)
$IPTABLES -A INPUT -m state --state NEW -p udp -m length --length 350:65535 -j REJECT

# SAMY Attack
$IPTABLES -A INPUT -m state --state NEW -p udp -m string --string "SAMPY" --algo bm --to 60 -j DROP
$IPTABLES -A INPUT -m state --state NEW -p udp -m string --string "HTTP/1.1 200 OK" --algo bm --to 75 -j DROP

# NTP Amplification
$IPTABLES -t raw -A PREROUTING -p udp --sport 123 -j DROP

# Block known-bad IPs (see http://www.dshield.org/top10.php).
# Top 10
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

# Drop any traffic from IANA-reserved IPs.
#------------------------------------------------------------------------------

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

# Block Packets With Bogus TCP Flags.
#------------------------------------------------------------------------------
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN,RST,PSH,ACK,URG NONE -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,SYN FIN,SYN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,RST FIN,RST -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags FIN,ACK FIN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,URG URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,FIN FIN -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ACK,PSH PSH -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL NONE -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL FIN,PSH,URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,FIN,PSH,URG -j DROP
$IPTABLES -t mangle -A PREROUTING -p tcp --tcp-flags ALL SYN,RST,ACK,FIN,URG -j DROP

# Selectively allow certain outbound and inbound connections, block the rest.
#------------------------------------------------------------------------------

# Allow outgoing SSH requests.
$IPTABLES -A OUTPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT
$IPTABLES -A OUTPUT -m state --state NEW -p udp --dport 10010 -j ACCEPT

# Selectively allow certain inbound connections, block the rest.
#------------------------------------------------------------------------------

# Allow incoming SSH requests.
$IPTABLES -A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT
$IPTABLES -A INPUT -m state --state NEW -p udp --dport 10010 -j ACCEPT

# Selectively allow certain inbound and outbound connections, block the rest.
#------------------------------------------------------------------------------

#$IPTABLES -A INPUT -s 86.121.210.186 -j ACCEPT
#$IPTABLES -A OUTPUT -d 86.121.210.186 -j ACCEPT

# Explicitly log and reject everything else.
#------------------------------------------------------------------------------

# Use REJECT instead of REJECTLOG if you don't need/want logging.
$IPTABLES -A INPUT -j REJECTLOG
$IPTABLES -A OUTPUT -j REJECTLOG
$IPTABLES -A FORWARD -j REJECTLOG

#------------------------------------------------------------------------------
# Testing the firewall.
#------------------------------------------------------------------------------

# You should check/test that the firewall really works, using
# iptables -vnL, nmap, ping, telnet, ...

# Exit gracefully.
#------------------------------------------------------------------------------

echo "firewall started"

exit 0
