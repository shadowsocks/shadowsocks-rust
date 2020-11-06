#!/bin/bash

if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root" 1>&2
   exit 1
fi

# Strategy Route
ip -4 route add local 0/0 dev lo table 100
ip -4 rule add fwmark 0x2333/0x2333 table 100
#ip -6 route add local ::/0 dev lo table 100
#ip -6 rule add fwmark 0x2333/0x2333 table 100

iptables -t mangle -N SS
ip6tables -t mangle -N SS
# Reserved addresses
iptables -t mangle -A SS -d 0/8 -j RETURN
iptables -t mangle -A SS -d 127/8 -j RETURN
iptables -t mangle -A SS -d 10/8 -j RETURN
iptables -t mangle -A SS -d 169.254/16 -j RETURN
iptables -t mangle -A SS -d 172.16/12 -j RETURN
iptables -t mangle -A SS -d 192.168/16 -j RETURN
iptables -t mangle -A SS -d 224/4 -j RETURN
iptables -t mangle -A SS -d 240/4 -j RETURN
#ip6tables -t mangle -A SS -d ::1/128 -j RETURN
#ip6tables -t mangle -A SS -d fc00::/7 -j RETURN
#ip6tables -t mangle -A SS -d fe80::/10 -j RETURN

# TPROXY TCP/UDP mark 0x2333 to port 60080
iptables -t mangle -A SS -p udp -j TPROXY --on-port 60080 --tproxy-mark 0x2333/0x2333
iptables -t mangle -A SS -p tcp -j TPROXY --on-port 60080 --tproxy-mark 0x2333/0x2333
#ip6tables -t mangle -A SS -p udp -j TPROXY --on-port 60080 --tproxy-mark 0x2333/0x2333
#ip6tables -t mangle -A SS -p tcp -j TPROXY --on-port 60080 --tproxy-mark 0x2333/0x2333

# Apply
iptables -t mangle -A PREROUTING -j SS
#ip6tables -t mangle -A PREROUTING -j SS

# OUTPUT rules
iptables -t mangle -N SS-MASK
#ip6tables -t mangle -N SS-MASK
# Reserved addresses
iptables -t mangle -A SS-MASK -d 0/8 -j RETURN
iptables -t mangle -A SS-MASK -d 127/8 -j RETURN
iptables -t mangle -A SS-MASK -d 10/8 -j RETURN
iptables -t mangle -A SS-MASK -d 169.254/16 -j RETURN
iptables -t mangle -A SS-MASK -d 172.16/12 -j RETURN
iptables -t mangle -A SS-MASK -d 192.168/16 -j RETURN
iptables -t mangle -A SS-MASK -d 224/4 -j RETURN
iptables -t mangle -A SS-MASK -d 240/4 -j RETURN
#ip6tables -t mangle -A SS-MASK -d ::1/128 -j RETURN
#ip6tables -t mangle -A SS-MASK -d fc00::/7 -j RETURN
#ip6tables -t mangle -A SS-MASK -d fe80::/10 -j RETURN

# Bypass sslocal with mask 0xff (255)
iptables -t mangle -A SS-MASK -j RETURN -m mark --mark 0xff
#ip6tables -t mangle -A SS-MASK -j RETURN -m mark --mark 0xff

# Reroute
iptables -t mangle -A SS-MASK -p udp -j MARK --set-mark 0x2333/0x2333
iptables -t mangle -A SS-MASK -p tcp -j MARK --set-mark 0x2333/0x2333
#ip6tables -t mangle -A SS-MASK -p udp -j MARK --set-mark 0x2333/0x2333
#ip6tables -t mangle -A SS-MASK -p tcp -j MARK --set-mark 0x2333/0x2333

# Apply
iptables -t mangle -A OUTPUT -j SS-MASK
#ip6tables -t mangle -A OUTPUT -j SS-MASK
