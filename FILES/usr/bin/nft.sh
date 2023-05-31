#!/usr/sbin/nft -f

flush ruleset

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
        
        chain clashboth {
                type filter hook prerouting priority mangle; policy accept;
                ip daddr @localnetwork return
                ip protocol tcp tproxy to 127.0.0.1:1082 meta mark set 1
                ip protocol udp tproxy to 127.0.0.1:1082 meta mark set 1
        }

        chain fakeping {
                type nat hook prerouting priority 0; policy accept;
                ip protocol icmp dnat to 127.0.0.1
        }

}
