#
# Regular cron jobs for the shadowsocks-rust package
#
0 4	* * *	root	[ -x /usr/bin/shadowsocks-rust_maintenance ] && /usr/bin/shadowsocks-rust_maintenance
