#!/bin/sh
IPREX4='([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])\.([0-9]{1,2}|1[0-9][0-9]|2[0-4][0-9]|25[0-5])'
IPREX6="^[0-9a-fA-F]{4}:[0-9a-fA-F:]+"

echo iso builder version: PPGW_version
echo run docker pull to fetch the latest image.
patch() {
  echo -e "\e[32m[Patch]\e[0m $*"
}
removegeoip() {
  if [ -f $root"/etc/config/clash/Country.mmdb" ]; then
    rm -rf $root"/etc/config/clash/Country.mmdb"
  fi
}
checkv4() {
  echo "$1" | grep -Eo "^$IPREX4$" >/dev/null
  return $?
}
checkv6() {
  echo "$1" | grep -Eo "^$IPREX6/*[0-9]{0,3}$" >/dev/null
  return $?
}
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

patchclash=0
if [ -f /data/clash ]; then
  ls /data/clash -lah
  patch clash ...
  cp /data/clash $root"/usr/bin/"
  chmod +x $root"/usr/bin/clash"
  patchclash=1
  $root"/usr/bin/clash" -v
else
  ver=mihomo_compatible
  if [ "$MI" = "3" ]; then
    ver=mihomo_v3
  fi
  patch Use the embedded Mihomo ..."$ver"
  cp /clash/$ver $root"/usr/bin/clash"
  chmod +x $root"/usr/bin/clash"
  patchclash=1
  $root"/usr/bin/clash" -v
fi
if [ -f /data/network.ini ]; then
  ls -lah /data/network.ini
  patch network.ini ...
  sed 's/\r/\n/g' "/data/network.ini" | grep -E "^[_a-zA-Z0-9]+=" >"/tmp/network.ini"
  . /tmp/network.ini
  dnslist=""$dns1" "$dns2" "$dns""
  if ! checkv4 "$dns1"; then
    dns1=$(echo "$dnslist" | grep -Eo "$IPREX4" | head -1)
  fi
  if [ "$dns1" = "$dns2" ] || ! checkv4 "$dns2"; then
    dns2=""
  fi
  ipv4_valid=0
  if checkv4 "$ip" && checkv4 "$mask" && checkv4 "$gw" && checkv4 "$dns1"; then
    if [ "$ip" = "$gw" ]; then
      echo "Error: ip=gw=\"$ip\" ! The network IP address should not be equal to the gateway."
      ipv4_valid=0
    else
      ipv4_valid=1
    fi
    patch "IPv4 static : ip=$ip mask=$mask gw=$gw"
  else
    patch "No valid static IPv4 configuration, will keep DHCPv4 configuration."
  fi
  ipv6_mode=""
  if [ "$ip6" = "auto" ]; then
    ipv6_mode="dhcpv6"
    patch "IPv6 auto mode (DHCPv6 + SLAAC) enabled."
  elif checkv6 "$ip6" && checkv6 "$gw6"; then
    ipv6_mode="static"
    patch "IPv6 static : ip6=$ip6 gw6=$gw6"
  elif [ -n "$ula" ]; then
    patch "WARNING: ULA is set but no IPv6 (ip6/gw6) configured. ULA alone usually needs an upstream IPv6, suggest setting ip6=auto."
  else
    patch "No IPv6 configuration, IPv6 will be disabled."
  fi
  network_config="${root}/etc/config/network"
  cat >"$network_config" <<EOF
config interface 'loopback'
	option device 'lo'
	option proto 'static'
	option ipaddr '127.0.0.1'
	option netmask '255.0.0.0'

EOF
  if [ $ipv4_valid -eq 1 ]; then
    cat >>"$network_config" <<EOF
config interface 'eth0'
	option device 'eth0'
	option proto 'static'
	option ipaddr '$ip'
	option netmask '$mask'
	option gateway '$gw'
EOF
    [ -n "$dns1" ] && echo "	option dns '$dns1${dns2:+ }${dns2}'" >>"$network_config"
  else
    cat >>"$network_config" <<EOF
config interface 'eth0'
	option device 'eth0'
	option proto 'dhcp'
EOF
  fi
  if [ -z "$ipv6_mode" ] && [ -z "$ula" ]; then
    echo "	option ipv6 '0'" >>"$network_config"
    rm -rf "$root"/etc/odhcp6c.user
    rm -rf "$root"/etc/odhcp6c.user.d
    rm -rf "$root"/lib/netifd/proto/dhcpv6.sh
    rm -rf "$root"/lib/netifd/dhcpv6.script
    rm -rf "$root"/lib/upgrade/keep.d/odhcp6c
    rm -rf "$root"/usr/sbin/odhcp6c
    rm -rf "$root"/usr/sbin/odhcpd
  fi
  echo "" >>"$network_config"

  if [ "$ipv6_mode" = "dhcpv6" ]; then
    cat >>"$network_config" <<EOF
config interface 'eth06'
	option device 'eth0'
	option proto 'dhcpv6'
	option reqaddress 'try'
	option reqprefix 'no'
EOF
  elif [ "$ipv6_mode" = "static" ]; then
    cat >>"$network_config" <<EOF
config interface 'eth06'
	option device 'eth0'
	option proto 'static'
	option ip6addr '$ip6'
	option ip6gw '$gw6'
EOF
  fi
  if [ -n "$ula" ]; then
    patch "Custom ULA configuration detected: $ula"
    cat >>"$network_config" <<EOF

config interface 'eth06u'
	option device 'eth0'
	option proto 'static'
	option ip6addr '$ula'
EOF
  fi
  if [ -n "$localnet" ]; then
    patch "Custom localnet configuration detected: $localnet"
    reserved_ips="0.0.0.0/8, 127.0.0.0/8, 224.0.0.0/4, 240.0.0.0-255.255.255.255"
    full_localnet="$reserved_ips, $localnet"
    # Patch nft.sh
    sed -i '/set localnetwork {/,/}/ {
      /elements = {/,/}/c\
                elements = { '"$full_localnet"' }
    }' "$root/usr/bin/nft.sh"
  fi
  if [ -n "$localnet6" ]; then
    patch "Custom localnet6 configuration detected: $localnet6"
    reserved_ips6="::1/128, ::/128, fe80::/10, fc00::/7, ff00::/8"
    full_localnet6="$reserved_ips6, $localnet6"
    # Patch nft.sh
    sed -i '/set localnetwork6/,/}/ {
      /elements = {/,/}/c\
                elements = { '"$full_localnet6"' }
    }' "$root/usr/bin/nft.sh"
  fi
fi

if [ -f /data/ppgwurl.ini ]; then
  if grep -q "ppgwurl=" /data/ppgwurl.ini; then
    ls -lah /data/ppgwurl.ini
    patch ppgwurl.ini ...
    sed 's/\r/\n/g' "/data/ppgwurl.ini" | grep "ppgwurl=" >$root"/www/ppgwurl.ini"
  fi
fi

if [ -f /data/ppgw.ini ]; then
  ls -lah /data/ppgw.ini
  patch ppgw.ini ...
  sed 's/\r/\n/g' "/data/ppgw.ini" | grep -E "^[_a-zA-Z0-9]+=" >$root"/www/ppgw.ini"
fi

if [ -f /data/custom.yaml ]; then
  ls -lah /data/custom.yaml
  patch custom.yaml ...
  sed 's/\r/\n/g' /data/custom.yaml >$root"/www/custom.yaml"
fi

if [ -f /data/custom.ovpn ]; then
  ls -lah /data/custom.ovpn
  patch custom.ovpn ...
  sed 's/\r$//' /data/custom.ovpn >$root"/www/custom.ovpn"
fi
if [ -f /data/ppsub.json ]; then
  ls -lah /data/ppsub.json
  patch ppsub.json ...
  cp /data/ppsub.json $root"/www/ppsub.json"
fi
if [ $patchclash -eq 1 ]; then
  if [ "$GEO" = "yes" ] || [ "$geo" = "yes" ]; then
    patch Add geo data ...
    cp /geodata/GeoSite.dat $root"/etc/config/clash/GeoSite.dat"
    cp /geodata/GeoIP.dat $root"/etc/config/clash/GeoIP.dat"
    cp /geodata/ASN.mmdb $root"/etc/config/clash/ASN.mmdb"
    cp /geodata/update.log $root"/etc/config/clash/update.log"
    removegeoip
  fi
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
mv /tmp/paopao-gateway-x86-64-custom.iso /data/ppgw-rPPGW_version-"$sha".iso
ls -lah /data/ppgw-rPPGW_version-"$sha".iso
rm -rf /tmp/ /*sh
