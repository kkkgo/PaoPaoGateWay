#!/bin/sh
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
. /tmp/ppgw.ini 2>/dev/tty0
dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
if [ -z "$dns_ip" ]; then
    dns_ip="223.5.5.5"
fi

if [ -z "$dns_port" ]; then
    dns_port="53"
fi
/usr/sbin/nft -f - <<EOF
flush ruleset

define DNS_O1 = $dns1
define DNS_O2 = $dns2
define DNS_R_IP = $dns_ip
define DNS_R_PORT = $dns_port

table ip ppgw {
        set original_dns {
                type ipv4_addr
                elements = { \$DNS_O1, \$DNS_O2 }
        }
        chain hijackdns {
                type nat hook output priority dstnat; policy accept;
                meta skuid 65534 accept
                ip daddr @original_dns udp dport 53 dnat to \$DNS_R_IP:\$DNS_R_PORT
        }
}
EOF
