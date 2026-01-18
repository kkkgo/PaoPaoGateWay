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

/usr/sbin/nft -f - << EOF
flush ruleset

define DNS_O1 = $dns1
define DNS_O2 = $dns2
define DNS_R_IP = $dns_ip
define DNS_R_PORT = $dns_port

table ip ppgw {
        set localnetwork {
                typeof ip daddr
                flags interval
                elements = {
                        0.0.0.0/8,
                        127.0.0.0/8,
                        10.0.0.0/8,
                        169.254.0.0/16,
                        172.16.0.0/12,
                        192.168.0.0/16,
                        224.0.0.0/4, 
                        240.0.0.0-255.255.255.255
                }
        }
        set original_dns {
                type ipv4_addr
                elements = { \$DNS_O1, \$DNS_O2 }
        }
        chain clashboth {
                type filter hook prerouting priority mangle; policy accept;
                ip daddr @localnetwork return
#forsniff                udp dport 443 reject
                ip protocol tcp tproxy to 127.0.0.1:1082 meta mark set 1
                ip protocol udp tproxy to 127.0.0.1:1082 meta mark set 1
        }

        chain fakeping {
                type nat hook prerouting priority 0; policy accept;
                ip protocol icmp dnat to 127.0.0.1
        }
        chain hijackdns {
                type nat hook output priority dstnat; policy accept;
                meta skuid 65534 accept
                ip daddr @original_dns udp dport 53 dnat to \$DNS_R_IP:\$DNS_R_PORT
        }
}
EOF