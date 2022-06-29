#!/bin/sh
# vim:sw=4:ts=4:et

set -e

if [ -z "${SS_ENTRYPOINT_QUIET_LOGS:-}" ]; then
    exec 3>&1
else
    exec 3>/dev/null
fi

if [ "$1" = "sslocal" -o "$1" = "ssserver" -o "$1" = "ssmanager" -o "$1" = "ssservice" ]; then
    if [ -f "/etc/shadowsocks-rust/config.json" ]; then
        echo >&3 "$0: Configuration complete; ready for start up"
    else
        echo >&3 "$0: No configuration files found in /etc/shadowsocks-rust, skipping configuration"
    fi
fi

exec "$@"