#!/bin/sh

echo iso builder version: PPGW_version
echo run docker pull to fetch the latest image.
json='{
    "log": {
        "level": "info"
    },
    "inbounds": [
        {
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "127.0.0.1",
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "listen_port": 1081
        }
    ],
    "outbounds": [
        {
            "type": "socks",
            "tag": "socks-clash",
            "server": "127.0.0.1",
            "server_port": 1080
        },
        {
            "type": "direct",
            "tag": "free"
        },
        {
            "type": "block",
            "tag": "block-quic"
        }
    ],
    "route": {
        "final": "socks-clash",
        "rules": [
            {
                "protocol": [
                    "quic",
                    "bitTorrent"
                ],
                "outbound": "block-quic"
            }
        ]
    }
}'

dnsjson='{
    "log": {
        "level": "info"
    },
    "dns": {
        "servers": [
            {
                "tag": "trustdns",
                "address": "udp://dns_ip:dns_port",
                "strategy": "prefer_ipv4",
                "detour": "free"
            }
        ]
    },
    "inbounds": [
        {
            "type": "tproxy",
            "tag": "tproxy-in",
            "listen": "127.0.0.1",
            "sniff": true,
            "sniff_override_destination": true,
            "sniff_timeout": "300ms",
            "domain_strategy": "prefer_ipv4",
            "listen_port": 1081
        }
    ],
    "outbounds": [
        {
            "type": "socks",
            "tag": "socks-clash",
            "server": "127.0.0.1",
            "server_port": 1080
        },
        {
            "type": "direct",
            "tag": "free"
        },
        {
            "type": "block",
            "tag": "block-quic"
        }
    ],
    "route": {
        "final": "socks-clash",
        "rules": [
            {
                "protocol": [
                    "quic"
                ],
                "outbound": "block-quic"
            }
        ]
    }
}'

echo Patching new iso ...
7z x -p"$sha" -o"/tmp/" /root.7z >/dev/null
cdroot=/tmp/cdrom
mkdir -p $cdroot
tar -xf /tmp/ppgwroot.tar -C $cdroot >/dev/null
rm /tmp/ppgwroot.tar /root.7z
mkdir $cdroot/rootfs
mv $cdroot/initrd.gz $cdroot/rootfs
cd $cdroot/rootfs || exit
gunzip -c initrd.gz | cpio -idmv >/dev/null 2>&1
rm initrd.gz
root=$cdroot/rootfs

if [ -f /data/Country.mmdb ]; then
    ls -lah /data/Country.mmdb
    echo Patching Country.mmdb...
    cp /data/Country.mmdb $root"/etc/config/clash/Country.mmdb"
fi

if [ "$SNIFF" = "yes" ] || [ "$SNIFF" = "dns" ] || [ "$sniff" = "yes" ] || [ "$sniff" = "dns" ]; then
    echo Patching sniff...
    mkdir -p $root"/etc/config/sing-box"
    echo "$json" >$root"/etc/config/sing-box/sniff.json"
    sed -i 's/1082/1081/g' $root"/usr/bin/nft.sh"
    sed -i 's/1082/1081/g' $root"/usr/bin/nft_tcp.sh"
    cp /sing-box $root"/usr/bin/"
fi

# if [ "$SNIFF" = "dns" ]; then
#     echo Patching sniff with dns...
#     mkdir -p $root"/etc/config/sing-box"
#     echo "$dnsjson" >$root"/etc/config/sing-box/sniff.json"
#     sed -i 's/1082/1081/g' $root"/usr/bin/nft.sh"
#     sed -i 's/1082/1081/g' $root"/usr/bin/nft_tcp.sh"
#     cp /sing-box $root"/usr/bin/"
#     touch $root"/www/sniffdns"
# fi

if [ -f /data/clash ]; then
    ls -lah /data/clash
    echo Patching clash...
    touch $root"/www/clash_core"
    cp /data/clash $root"/usr/bin/"
    chmod +x $root"/usr/bin/clash"
fi
if [ -f /data/network.ini ]; then
    ls -lah /data/network.ini
    echo Patching network...
    sed 's/\r$//' "/data/network.ini" | grep -E "^[_a-zA-Z0-9]+=" >"/tmp/network.ini"
    . /tmp/network.ini
    if [ -z "$ip" ]; then
        echo "Error: network.ini ip not found."
        exit
    fi
    if [ -z "$mask" ]; then
        echo "Error: network.ini mask not found."
        exit
    fi
    if [ -z "$gw" ]; then
        echo "Error: network.ini gw not found."
        exit
    fi
    if [ "$ip" = "$gw" ]; then
        echo "Error: ip=gw=""$ip"" ! The network IP address should not be equal to the gateway."
        exit
    fi
    cat >$root"/etc/config/network" <<EOF
config interface 'loopback'
    option device 'lo'
    option proto 'static'
    option ipaddr '127.0.0.1'
    option netmask '255.0.0.0'

config interface 'eth0'
    option device 'eth0'
    option proto 'static'
    option ipaddr '$ip'
    option netmask '$mask'
    option gateway '$gw'
EOF
    if [ -z "$dns1" ]; then
        if [ -n "$dns" ]; then
            dns1=$dns
        else
            if [ -n "$dns2" ]; then
                dns1=$dns2
            else
                echo "Error: network.ini dns1=? or dns2=? not found."
                exit
            fi
        fi
    fi
    if [ -n "$dns2" ]; then
        echo "    option dns '$dns1 $dns2'" >>$root"/etc/config/network"
    else
        echo "    option dns '$dns1'" >>$root"/etc/config/network"
    fi
fi
if [ -f /data/ppgwurl.ini ]; then
    if grep -q "ppgwurl=" /data/ppgwurl.ini; then
        ls -lah /data/ppgwurl.ini
        echo Patching ppgwurl.ini...
        sed 's/\r$//' "/data/ppgwurl.ini" | grep "ppgwurl=" >$root"/www/ppgwurl.ini"
    fi
fi
if [ -f /data/ppgw.ini ]; then
    ls -lah /data/ppgw.ini
    echo Patching ppgw.ini...
    sed 's/\r$//' "/data/ppgw.ini" | grep -E "^[_a-zA-Z0-9]+=" >$root"/www/ppgw.ini"
fi

if [ -f /data/custom.yaml ]; then
    ls -lah /data/custom.yaml
    echo Patching custom.yaml...
    sed 's/\r$//' /data/custom.yaml >$root"/www/custom.yaml"
fi

if [ -f /data/custom.ovpn ]; then
    ls -lah /data/custom.ovpn
    echo Patching custom.ovpn...
    cp /data/custom.ovpn $root"/www/custom.ovpn"
fi

echo "Making iso..."
cd $root || exit
find . | cpio -H newc -o | gzip -9 >$cdroot/initrd.gz
cd $cdroot || exit
rm -rf rootfs
cp -r /isolinux .
xorriso -as mkisofs -o /tmp/paopao-gateway-x86-64-custom.iso \
    -isohybrid-mbr isolinux/isolinux.bin \
    -c isolinux/boot.cat -b isolinux/isolinux.bin \
    -no-emul-boot -boot-load-size 4 -boot-info-table \
    -eltorito-alt-boot -e /isolinux/efi.img \
    -no-emul-boot -isohybrid-gpt-basdat -V "paopao-gateway" $cdroot >/dev/null 2>&1

sha=$(sha256sum /tmp/paopao-gateway-x86-64-custom.iso | grep -Eo "^[0-9a-z]{7}")
mv /tmp/paopao-gateway-x86-64-custom.iso /data/paopao-gateway-x86-64-custom-"$sha".iso
ls -lah /data/paopao-gateway-x86-64-custom-"$sha".iso
rm -rf /tmp/ /*sh
