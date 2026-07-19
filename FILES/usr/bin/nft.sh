#!/bin/sh
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
if [ -f /tmp/ppgw.ini ]; then
    . /tmp/ppgw.ini 2>/dev/tty0
fi
dns1=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | head -1)
dns2=$(grep nameserver /etc/resolv.conf | grep -Eo "$IPREX4" | tail -1)
if [ -z "$dns_ip" ]; then
    dns_ip="223.5.5.5"
fi

if [ -z "$dns_port" ]; then
    dns_port="53"
fi

if [ -z "$udp_enable" ]; then
    udp_enable="no"
fi

# Auto-detect IPv6
if grep -q -r eth06 /etc/config/network 2>/dev/null; then
    ipv6="yes"
else
    ipv6="no"
fi

# openport controls whether external
if [ -z "$openport" ]; then
    openport="no"
fi
if [ "$openport" = "yes" ]; then
    openport_input_rule=""
else
    openport_input_rule="                iifname \"lo\" accept
                meta l4proto {tcp, udp} th dport 1080 drop"
fi

block_quic=$(echo "$box" | grep -Eo "block_quic[ ]*=[ ]*[a-zA-Z]+" | grep -Eo "(true|false)" | head -1)
if [ -z "$block_quic" ]; then
    block_quic="true"
fi

if [ "$block_quic" = "true" ]; then
    udp_rules="                udp dport 443 reject"
fi
if [ "$udp_enable" = "yes" ]; then
    udp_proto_rule="                ip protocol udp tproxy to 127.0.0.1:1081 meta mark set 1"
else
    udp_proto_rule="                ip protocol udp drop"
fi
if [ -n "$udp_rules" ]; then
    udp_rules="$udp_rules
$udp_proto_rule"
else
    udp_rules="$udp_proto_rule"
fi

# --- IPv6 variants (only used when ipv6=yes) ---
if [ "$openport" = "yes" ]; then
    openport_input_rule6=""
else
    openport_input_rule6="                iifname \"lo\" accept
                meta l4proto {tcp, udp} th dport 1080 drop"
fi
if [ "$block_quic" = "true" ]; then
    udp_rules6="                udp dport 443 reject"
fi
if [ "$udp_enable" = "yes" ]; then
    udp_proto_rule6="                meta l4proto udp tproxy to [::1]:1081 meta mark set 1"
else
    udp_proto_rule6="                meta l4proto udp drop"
fi
if [ -n "$udp_rules6" ]; then
    udp_rules6="$udp_rules6
$udp_proto_rule6"
else
    udp_rules6="$udp_proto_rule6"
fi

if [ "$ipv6" = "yes" ]; then
    IP6_TABLE="
table ip6 ppgw {
        set localnetwork6 {
                typeof ip6 daddr
                flags interval
                elements = {
                        ::1/128,
                        ::/128,
                        fe80::/10,
                        fc00::/7,
                        ff00::/8
                }
        }
        chain ppgw_tproxy6 {
                type filter hook prerouting priority mangle; policy accept;
                ip6 daddr @localnetwork6 return
$udp_rules6
                meta l4proto tcp tproxy to [::1]:1081 meta mark set 1
        }
        chain ppgw_input6 {
                type filter hook input priority filter; policy accept;
$openport_input_rule6
        }
}
"
else
    IP6_TABLE=""
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
        chain ppgw_tproxy {
                type filter hook prerouting priority mangle; policy accept;
                ip daddr @localnetwork return
$udp_rules
                ip protocol tcp tproxy to 127.0.0.1:1081 meta mark set 1
        }

        chain ppgw_input {
                type filter hook input priority filter; policy accept;
$openport_input_rule
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
$IP6_TABLE
EOF