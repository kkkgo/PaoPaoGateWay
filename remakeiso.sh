#!/bin/sh
echo Patching new iso ...
7z x -p"$sha" -o"/tmp/" /root.7z >/dev/null
root=/tmp/remakeroot
mkdir -p $root
tar -xf /tmp/ppgwroot.tar -C $root >/dev/null
rm /tmp/ppgwroot.tar /root.7z
if [ "$GEOIP" = "full" ]; then
    echo "Pacthing FULL GEOIP..."
    echo "Downloading full Country.mmdb..."
    wget https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb -O /tmp/Country-full.mmdb
    mmdbfull_hash=$(sha256sum /tmp/Country-full.mmdb | grep -Eo "[a-zA-Z0-9]{64}" | head -1)
    mmdbfull_down_hash=$(wget -q https://cdn.jsdelivr.net/gh/Loyalsoldier/geoip@release/Country.mmdb.sha256sum -O- | grep -Eo "[a-zA-Z0-9]{64}" | head -1)
    if [ "$mmdbfull_down_hash" = "$mmdbfull_hash" ]; then
        echo "New full Country.mmdb OK."
        mv /tmp/Country-full.mmdb $root"/etc/config/clash/Country.mmdb"
    else
        mv /Country-full.mmdb $root"/etc/config/clash/Country.mmdb"
    fi
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

echo "Making iso..."
xorriso -as mkisofs -R -b boot/grub/eltorito.img \
    -no-emul-boot -boot-info-table \
    -o /tmp/paopao-gateway-x86-64-custom.iso /tmp/remakeroot >/dev/null 2>&1

sha=$(sha256sum /tmp/paopao-gateway-x86-64-custom.iso | grep -Eo "^[0-9a-z]{7}")
mv /tmp/paopao-gateway-x86-64-custom.iso /data/paopao-gateway-x86-64-custom-"$sha".iso
ls -lah /data/paopao-gateway-x86-64-custom-"$sha".iso
rm -rf /tmp/ /*sh
