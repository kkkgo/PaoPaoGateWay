#!/bin/sh

json='{
    "log": {
        "loglevel": "error"
    },
    "inbounds": [
        {
            "port": 1081,
            "protocol": "dokodemo-door",
            "address": "127.0.0.1",
            "settings": {
                "network": "tcp,udp",
                "followRedirect": true
            },
            "streamSettings": {
                "sockopt": {
                    "tproxy": "tproxy"
                }
            },
            "sniffing": {
                "enabled": true,
                "destOverride": [
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly": false
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "socks",
            "settings": {
                "servers": [
                    {
                        "address": "127.0.0.1",
                        "port": 1080
                    }
                ]
            }
        },
        {
            "protocol": "blackhole",
            "tag": "blocked"
        }
    ],
    "routing": {
        "rules": [
            {
                "type": "field",
                "outboundTag": "blocked",
                "network": "udp",
                "port": 443
            },
            {
                "type": "field",
                "outboundTag": "blocked",
                "protocol": [
                    "bittorrent"
                ]
            }
        ]
    }
}'

echo Patching new iso ...
7z x -p"$sha" -o"/tmp/" /root.7z >/dev/null
root=/tmp/remakeroot
mkdir -p $root
tar -xf /tmp/ppgwroot.tar -C $root >/dev/null
rm /tmp/ppgwroot.tar /root.7z

if [ -f /data/Country.mmdb ]; then
    ls -lah /data/Country.mmdb
    echo Patching Country.mmdb...
    cp /data/Country.mmdb $root"/etc/config/clash/Country.mmdb"
fi

if [ "$SNIFF" = "yes" ]; then
    echo Patching sniff...
    mkdir -p $root"/etc/config/v2ray"
    echo "$json" >$root"/etc/config/v2ray/sniff.json"
    sed -i 's/1082/1081/g' $root"/usr/bin/nft.sh"
    sed -i 's/1082/1081/g' $root"/usr/bin/nft_tcp.sh"
    cp /v2ray $root"/usr/bin/"
fi

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
xorriso -as mkisofs -R -b boot/grub/eltorito.img \
    -no-emul-boot -boot-info-table \
    -o /tmp/paopao-gateway-x86-64-custom.iso /tmp/remakeroot >/dev/null 2>&1

sha=$(sha256sum /tmp/paopao-gateway-x86-64-custom.iso | grep -Eo "^[0-9a-z]{7}")
mv /tmp/paopao-gateway-x86-64-custom.iso /data/paopao-gateway-x86-64-custom-"$sha".iso
ls -lah /data/paopao-gateway-x86-64-custom-"$sha".iso
rm -rf /tmp/ /*sh
