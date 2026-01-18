#!/bin/sh
echo $1
cd "$1"
rm etc/banner.failsafe
rm etc/device_info
rm etc/board.d/01_leds
rm -rf etc/capabilities
rm etc/init.d/gpio_switch
rm etc/init.d/led
rm etc/openwrt_release
rm etc/openwrt_version
rm etc/os-release
rm etc/rc.d/K10gpio_switch
rm etc/rc.d/S94gpio_switch
rm etc/rc.d/S96led
rm etc/sysupgrade.conf
rm -rf etc/rc.button
rm -rf etc/opkg
rm -rf lib/upgrade
rm -rf usr/lib/opkg
rm -rf usr/lib/os-release
rm sbin/firstboot
rm sbin/sysupgrade
rm sbin/wifi
rm -rf usr/lib/share/acl.d
rm -rf usr/lib/share/libubox
cd lib/preinit
rm 10_indicate_failsafe
rm 30_failsafe_wait
rm 40_run_failsafe_hook
rm 99_10_failsafe_dropbear
rm 99_10_failsafe_login
if [ -f /src/iso/root.7z ]; then
    rm /src/iso/root.7z
fi
rootfs="$(dirname "$1""/*")"
bootdir="$(dirname "$2""/*")"
echo "exec /sbin/init" > "$rootfs"/init
echo "echo" > "$rootfs"/sbin/wifi
chmod +x "$rootfs"/init
chmod +x "$rootfs"/sbin/wifi
cd $rootfs || exit
mkdir -p /tmp/cdrom
find . | cpio -H newc -o | gzip -9 >/tmp/cdrom/initrd.gz
cp "$bootdir"/boot/vmlinuz /tmp/cdrom/

packroot="/tmp/ppgwroot.tar"
tar -cf "$packroot" -C "/tmp/cdrom/" ./
rootsha=$(sha256sum $packroot | cut -d ' ' -f 1)
echo "$rootsha" >/src/iso/rootsha.txt
7z a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -bsp1 -bso1 -bse1 -y -p"$rootsha" "/src/iso/root.7z" "$packroot"
