#!/bin/sh /etc/rc.common

START=30

USE_PROCD=1

EXTRA_COMMANDS="set_firewall destroy"
EXTRA_HELP=<<EOF
	set_firewall Set firewall (iptable) rules
	destroy Remove all resources (ipset, firewall rules, ...)
EOF

set_firewall() {
    uci add firewall include
    uci rename 'firewall.@include[-1]=shadowsocks'
    uci set 'firewall.@include[-1].path=/usr/local/etc/iptables_mixed.include'
    uci set 'firewall.@include[-1].type=script'
    uci set 'firewall.@include[-1].reload=1'
    uci commit firewall

    # Initialize iptables rules
    /etc/init.d/firewall restart
}

destroy() {
    ipset destroy chnip
    ipset destroy gfwlist
    ipset destroy bypasslist
    ipset destroy chnip6
    ipset destroy gfwlist6
    ipset destroy bypasslist6

    uci delete 'firewall.shadowsocks'
    uci commit firewall

    # Delete iptables rules
    /etc/init.d/firewall restart

    # Delete strategy route rules
    ip -4 rule del fwmark 0x1 table 803
    ip -4 route del local 0.0.0.0/0 dev lo table 803
    ip -6 rule del fwmark 0x1 table 803
    ip -6 route del local ::/0 dev lo table 803
}

start_service() {
    SHADOWSOCKS_CAPABILITIES_CONFIG_PATH="/etc/capabilities/shadowsocks.json"
    SHADOWSOCKS_LOG_FILE_PATH="/var/log/shadowsocks"

    mkdir -p ${SHADOWSOCKS_LOG_FILE_PATH}
    if id "shadowsocks" &>/dev/null; then
        chown shadowsocks:shadowsocks -R ${SHADOWSOCKS_LOG_FILE_PATH}
    fi

    SHADOWSOCKS_CONFIG_PATH="/usr/local/etc/shadowsocks.json"
    SHADOWSOCKS_EXECUTABLE="/usr/local/bin/sslocal"
    SHADOWSOCKS_PARAMETERS="-c ${SHADOWSOCKS_CONFIG_PATH} --log-without-time --udp-max-associations 4192 --outbound-fwmark 255"
    SHADOWSOCKS_COMMAND="${SHADOWSOCKS_EXECUTABLE} ${SHADOWSOCKS_PARAMETERS}"

    procd_open_instance shadowsocks
    procd_set_param env RUST_BACKTRACE=1
    procd_set_param env NO_COLOR=1

    procd_set_param file ${SHADOWSOCKS_CONFIG_PATH}
    procd_set_param respawn
    procd_set_param reload_signal USR1
    procd_set_param limits nofile="10240 10240"
    procd_set_param limits core="unlimited"
    procd_set_param stdout 1
    procd_set_param stderr 1

    if id "shadowsocks" &>/dev/null; then
        if [ -x /sbin/ujail -a -e ${SHADOWSOCKS_CAPABILITIES_CONFIG_PATH} ]; then
            procd_add_jail shadowsocks requirejail
            procd_add_jail_mount ${SHADOWSOCKS_CONFIG_PATH}
            procd_set_param user shadowsocks
            procd_set_param group shadowsocks
            procd_set_param capabilities ${SHADOWSOCKS_CAPABILITIES_CONFIG_PATH}
            procd_set_param no_new_privs 1
            procd_set_param command ${SHADOWSOCKS_COMMAND}
        else
            procd_set_param user root
            procd_set_param command /usr/sbin/capsh --caps="cap_setpcap,cap_setuid,cap_setgid+ep cap_net_admin,cap_net_raw,cap_net_bind_service+eip" --keep=1 \
                                    --user="shadowsocks" --addamb="cap_net_admin,cap_net_raw,cap_net_bind_service" \
                                    --shell="${SHADOWSOCKS_EXECUTABLE}" -- ${SHADOWSOCKS_PARAMETERS}
        fi
    else
        procd_set_param user root
        procd_set_param command ${SHADOWSOCKS_COMMAND}
    fi

    SHADOWSOCKS6_CONFIG_PATH="/usr/local/etc/shadowsocks6.json"
    SHADOWSOCKS6_EXECUTABLE="/usr/local/bin/sslocal"
    SHADOWSOCKS6_PARAMETERS="-c ${SHADOWSOCKS6_CONFIG_PATH} --log-without-time --udp-max-associations 4192 --outbound-fwmark 255"
    SHADOWSOCKS6_COMMAND="${SHADOWSOCKS6_EXECUTABLE} ${SHADOWSOCKS6_PARAMETERS}"

    procd_set_param pidfile /var/run/shadowsocks.pid
    procd_close_instance

    procd_open_instance shadowsocks6
    procd_set_param env RUST_BACKTRACE=1
    procd_set_param env NO_COLOR=1

    procd_set_param file ${SHADOWSOCKS6_CONFIG_PATH}
    procd_set_param respawn
    procd_set_param reload_signal USR1
    procd_set_param limits nofile="10240 10240"
    procd_set_param limits core="unlimited"
    procd_set_param stdout 1
    procd_set_param stderr 1

    if id "shadowsocks" &>/dev/null; then
        if [ -x /sbin/ujail -a -e ${SHADOWSOCKS_CAPABILITIES_CONFIG_PATH} ]; then
            procd_add_jail shadowsocks6 requirejail
            procd_add_jail_mount ${SHADOWSOCKS6_CONFIG_PATH}
            procd_set_param user shadowsocks
            procd_set_param group shadowsocks
            procd_set_param capabilities ${SHADOWSOCKS_CAPABILITIES_CONFIG_PATH}
            procd_set_param no_new_privs 1
            procd_set_param command ${SHADOWSOCKS6_COMMAND}
        else
            procd_set_param user root
            procd_set_param command /usr/sbin/capsh --caps="cap_setpcap,cap_setuid,cap_setgid+ep cap_net_admin,cap_net_raw,cap_net_bind_service+eip" --keep=1 \
                                    --user="shadowsocks" --addamb="cap_net_admin,cap_net_raw,cap_net_bind_service" \
                                    --shell="${SHADOWSOCKS6_EXECUTABLE}" -- ${SHADOWSOCKS6_PARAMETERS}
        fi
    else
        procd_set_param user root
        procd_set_param command ${SHADOWSOCKS6_COMMAND}
    fi

    procd_set_param pidfile /var/run/shadowsocks6.pid
    procd_close_instance

    echo 'Started shadowsocks service'
}

service_stopped() {
    echo 'Stopped shadowsocks service'
}

service_triggers() {
    #procd_add_reload_interface_trigger "pppoe-wan"
    procd_add_interface_trigger "interface.*" "pppoe-wan" /etc/init.d/shadowsocks restart
}
