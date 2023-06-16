#!/bin/bash

iptables-save | grep -v shadowsocks- | iptables-restore
ip6tables-save | grep -v shadowsocks- | ip6tables-restore

### IPv4 RULES

# Create chnip ipset
ipset create chnip hash:net family inet -exist
ipset restore < /usr/local/etc/chnip.ipset

# Create gfwlist ipset
ipset create gfwlist hash:ip family inet timeout 7200 -exist
ipset create bypasslist hash:ip family inet timeout 7200 -exist

SHADOWSOCKS_REDIR_IP=0.0.0.0
SHADOWSOCKS_REDIR_PORT=60080

readonly IPV4_RESERVED_IPADDRS="\
0/8 \
10/8 \
100.64/10 \
127/8 \
169.254/16 \
172.16/12 \
192/24 \
192.0.2.0/24 \
192.88.99/24 \
192.168/16 \
198.18/15 \
198.51.100/24 \
203.0.113/24 \
224/4 \
240/4 \
255.255.255.255/32 \
"

## TCP+UDP
# Strategy Route
ip -4 rule del fwmark 0x1 table 803
ip -4 rule add fwmark 0x1 table 803
ip -4 route del local 0.0.0.0/0 dev lo table 803
ip -4 route add local 0.0.0.0/0 dev lo table 803

# TPROXY for LAN
iptables -t mangle -N shadowsocks-tproxy
# Skip LoopBack, Reserved
for addr in ${IPV4_RESERVED_IPADDRS}; do
   iptables -t mangle -A shadowsocks-tproxy -d "${addr}" -j RETURN
done

# Bypass LAN data
iptables -t mangle -A shadowsocks-tproxy -m addrtype --dst-type LOCAL -j RETURN
# Bypass sslocal's outbound data
iptables -t mangle -A shadowsocks-tproxy -m mark --mark 0xff/0xff -j RETURN
# UDP: Proxy gfwlist
iptables -t mangle -A shadowsocks-tproxy -m set --match-set gfwlist dst -p udp -j TPROXY --on-ip ${SHADOWSOCKS_REDIR_IP} --on-port ${SHADOWSOCKS_REDIR_PORT} --tproxy-mark 0x01/0x01
# UDP: Bypass CN IPs
iptables -t mangle -A shadowsocks-tproxy -m set --match-set chnip dst -p udp -j RETURN
iptables -t mangle -A shadowsocks-tproxy -m set --match-set bypasslist dst -p udp -j RETURN
# UDP: TPROXY UDP to 60080
iptables -t mangle -A shadowsocks-tproxy -p udp -j TPROXY --on-ip ${SHADOWSOCKS_REDIR_IP} --on-port ${SHADOWSOCKS_REDIR_PORT} --tproxy-mark 0x01/0x01
# TCP: Proxy gfwlist
iptables -t mangle -A shadowsocks-tproxy -m set --match-set gfwlist dst -p tcp -j TPROXY --on-ip ${SHADOWSOCKS_REDIR_IP} --on-port ${SHADOWSOCKS_REDIR_PORT} --tproxy-mark 0x01/0x01
# TCP: Bypass CN IPs
iptables -t mangle -A shadowsocks-tproxy -m set --match-set chnip dst -p tcp -j RETURN
iptables -t mangle -A shadowsocks-tproxy -m set --match-set bypasslist dst -p tcp -j RETURN
# TCP: TPROXY TCP to 60080
iptables -t mangle -A shadowsocks-tproxy -p tcp -j TPROXY --on-ip ${SHADOWSOCKS_REDIR_IP} --on-port ${SHADOWSOCKS_REDIR_PORT} --tproxy-mark 0x01/0x01


# TPROXY for Local
iptables -t mangle -N shadowsocks-tproxy-mark
# Skip LoopBack, Reserved
for addr in ${IPV4_RESERVED_IPADDRS}; do
   iptables -t mangle -A shadowsocks-tproxy-mark -d "${addr}" -j RETURN
done

# TCP: conntrack
iptables -t mangle -A shadowsocks-tproxy-mark -p tcp -m conntrack --ctdir REPLY -j RETURN
# Bypass sslocal's outbound data
iptables -t mangle -A shadowsocks-tproxy-mark -m mark --mark 0xff/0xff -j RETURN
iptables -t mangle -A shadowsocks-tproxy-mark -m owner --uid-owner shadowsocks -j RETURN
# Proxy gfwlist
iptables -t mangle -A shadowsocks-tproxy-mark -m set --match-set gfwlist dst -j MARK --set-xmark 0x01/0xffffffff
# Bypass CN IPs
iptables -t mangle -A shadowsocks-tproxy-mark -m set --match-set chnip dst -j RETURN
# UDP: Set MARK and reroute
iptables -t mangle -A shadowsocks-tproxy-mark -p udp -j MARK --set-xmark 0x01/0xffffffff
# TCP: Set MARK and reroute
iptables -t mangle -A shadowsocks-tproxy-mark -p tcp -j MARK --set-xmark 0x01/0xffffffff

# Apply TPROXY to LAN
iptables -t mangle -A PREROUTING -p udp -j shadowsocks-tproxy
iptables -t mangle -A PREROUTING -p tcp -j shadowsocks-tproxy
#iptables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j shadowsocks-tproxy
# Apply TPROXY for Local
iptables -t mangle -A OUTPUT -p udp -j shadowsocks-tproxy-mark
iptables -t mangle -A OUTPUT -p tcp -j shadowsocks-tproxy-mark
#iptables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j shadowsocks-tproxy-mark

# DIVERT rules
# For optimizing TCP
# iptables -t mangle -N shadowsocks-divert
# iptables -t mangle -A shadowsocks-divert -j MARK --set-mark 1
# iptables -t mangle -A shadowsocks-divert -j ACCEPT
# iptables -t mangle -I PREROUTING -p tcp -m socket -j shadowsocks-divert

### IPv6 RULES

# Create chnip6 ipset
ipset create chnip6 hash:net family inet6 -exist
ipset restore < /usr/local/etc/chnip6.ipset

# Create gfwlist6 ipset
ipset create gfwlist6 hash:ip family inet6 timeout 7200 -exist
ipset create bypasslist6 hash:ip family inet6 timeout 7200 -exist

SHADOWSOCKS6_REDIR_IP=::
SHADOWSOCKS6_REDIR_PORT=60081

readonly IPV6_RESERVED_IPADDRS="\
::/128 \
::1/128 \
::ffff:0:0/96 \
::ffff:0:0:0/96 \
64:ff9b::/96 \
100::/64 \
2001::/32 \
2001:20::/28 \
2001:db8::/32 \
2002::/16 \
fc00::/7 \
fe80::/10 \
ff00::/8 \
"

## TCP+UDP
# Strategy Route
ip -6 rule del fwmark 0x1 table 803
ip -6 rule add fwmark 0x1 table 803
ip -6 route del local ::/0 dev lo table 803
ip -6 route add local ::/0 dev lo table 803

# TPROXY for LAN
ip6tables -t mangle -N shadowsocks-tproxy
# Skip LoopBack, Reserved
for addr in ${IPV6_RESERVED_IPADDRS}; do
   ip6tables -t mangle -A shadowsocks-tproxy -d "${addr}" -j RETURN
done

# Bypass LAN data
ip6tables -t mangle -A shadowsocks-tproxy -m addrtype --dst-type LOCAL -j RETURN
# Bypass sslocal's outbound data
ip6tables -t mangle -A shadowsocks-tproxy -m mark --mark 0xff/0xff -j RETURN
# UDP: Proxy gfwlist6
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set gfwlist6 dst -p udp -j TPROXY --on-ip ${SHADOWSOCKS6_REDIR_IP} --on-port ${SHADOWSOCKS6_REDIR_PORT} --tproxy-mark 0x01/0x01
# UDP: Bypass CN IPs
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set chnip6 dst -p udp -j RETURN
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set bypasslist6 dst -p udp -j RETURN
# UDP: TPROXY UDP to 60081
ip6tables -t mangle -A shadowsocks-tproxy -p udp -j TPROXY --on-ip ${SHADOWSOCKS6_REDIR_IP} --on-port ${SHADOWSOCKS6_REDIR_PORT} --tproxy-mark 0x01/0x01
# TCP: Proxy gfwlist6
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set gfwlist6 dst -p tcp -j TPROXY --on-ip ${SHADOWSOCKS6_REDIR_IP} --on-port ${SHADOWSOCKS6_REDIR_PORT} --tproxy-mark 0x01/0x01
# TCP: Bypass CN IPs
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set chnip6 dst -p tcp -j RETURN
ip6tables -t mangle -A shadowsocks-tproxy -m set --match-set bypasslist6 dst -p tcp -j RETURN
# TCP: TPROXY UDP to 60081
ip6tables -t mangle -A shadowsocks-tproxy -p tcp -j TPROXY --on-ip ${SHADOWSOCKS6_REDIR_IP} --on-port ${SHADOWSOCKS6_REDIR_PORT} --tproxy-mark 0x01/0x01

# TPROXY for Local
ip6tables -t mangle -N shadowsocks-tproxy-mark
# Skip LoopBack, Reserved
for addr in ${IPV6_RESERVED_IPADDRS}; do
   ip6tables -t mangle -A shadowsocks-tproxy-mark -d "${addr}" -j RETURN
done

# TCP: conntrack
ip6tables -t mangle -A shadowsocks-tproxy-mark -p tcp -m conntrack --ctdir REPLY -j RETURN
# Bypass sslocal's outbound data
ip6tables -t mangle -A shadowsocks-tproxy-mark -m mark --mark 0xff/0xff -j RETURN
ip6tables -t mangle -A shadowsocks-tproxy-mark -m owner --uid-owner shadowsocks -j RETURN
# Proxy gfwlist6
ip6tables -t mangle -A shadowsocks-tproxy-mark -m set --match-set gfwlist6 dst -j MARK --set-xmark 0x01/0xffffffff
# Bypass CN IPs
ip6tables -t mangle -A shadowsocks-tproxy-mark -m set --match-set chnip6 dst -j RETURN
# Set MARK and reroute
ip6tables -t mangle -A shadowsocks-tproxy-mark -p udp -j MARK --set-xmark 0x01/0xffffffff
ip6tables -t mangle -A shadowsocks-tproxy-mark -p tcp -j MARK --set-xmark 0x01/0xffffffff

# Apply TPROXY to LAN
ip6tables -t mangle -A PREROUTING -p udp -j shadowsocks-tproxy
ip6tables -t mangle -A PREROUTING -p tcp -j shadowsocks-tproxy
#ip6tables -t mangle -A PREROUTING -p udp -m addrtype ! --src-type LOCAL ! --dst-type LOCAL -j shadowsocks-tproxy
# Apply TPROXY for Local
ip6tables -t mangle -A OUTPUT -p udp -j shadowsocks-tproxy-mark
ip6tables -t mangle -A OUTPUT -p tcp -j shadowsocks-tproxy-mark
#ip6tables -t mangle -A OUTPUT -p udp -m addrtype --src-type LOCAL ! --dst-type LOCAL -j shadowsocks-tproxy-mark

# DIVERT rules
# For optimizing TCP
# ip6tables -t mangle -N shadowsocks-divert
# ip6tables -t mangle -A shadowsocks-divert -j MARK --set-mark 1
# ip6tables -t mangle -A shadowsocks-divert -j ACCEPT
