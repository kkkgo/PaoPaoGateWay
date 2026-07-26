#!/bin/sh

echo $1
cd "$1"
rm -f etc/banner.failsafe
rm -f etc/device_info
rm -f etc/board.d/01_leds
rm -rf etc/capabilities
rm -rf etc/apk
rm -rf etc/profile.d
rm -rf lib/apk
sed -i '/add_list system\.ntp\.server/d' bin/config_generate
rm -f etc/init.d/gpio_switch
rm -f etc/init.d/led
rm -f etc/openwrt_release
rm -f etc/openwrt_version
rm -f etc/os-release
rm -f etc/rc.d/K10gpio_switch
rm -f etc/rc.d/S94gpio_switch
rm -f etc/rc.d/S96led
rm -f etc/sysupgrade.conf
rm -rf etc/rc.button
rm -rf etc/opkg
rm -rf lib/upgrade
rm -rf usr/lib/opkg
rm -rf usr/lib/os-release
rm -f sbin/firstboot
rm -f sbin/sysupgrade
rm -f sbin/wifi
rm -f sbin/led.sh
rm -rf usr/lib/share/acl.d
rm -rf usr/lib/share/libubox
cd lib/preinit
rm -f 10_indicate_failsafe
rm -f 30_failsafe_wait
rm -f 40_run_failsafe_hook
rm -f 99_10_failsafe_dropbear
rm -f 99_10_failsafe_login
if [ -f /src/iso/root.7z ]; then
    rm /src/iso/root.7z
fi
rootfs="$(dirname "$1""/*")"
bootdir="$(dirname "$2""/*")"
echo "exec /sbin/init" >"$rootfs"/init
echo "echo" >"$rootfs"/sbin/wifi
chmod +x "$rootfs"/init
chmod +x "$rootfs"/sbin/wifi

packdir=/tmp/ppgwpack
rm -rf "$packdir"
mkdir -p "$packdir"/boot/grub "$packdir"/efi/boot
cd $rootfs || exit
find . | cpio -H newc -o | gzip -9 >"$packdir"/initrd.gz
cp "$bootdir"/boot/vmlinuz "$packdir"/boot/vmlinuz
cp "$bootdir"/boot/grub/efi.img "$packdir"/boot/grub/efi.img
cp "$bootdir"/efi/boot/bootaa64.efi "$packdir"/efi/boot/bootaa64.efi

cat <<EOF >"$packdir"/boot/grub/grub.cfg
set default="0"
set timeout="0"

menuentry "PaoPaoGateway" {
	linux /boot/vmlinuz console=tty0 console=ttyAMA0,115200 earlycon
	initrd /boot/initrd
}
EOF
ls -lah "$packdir" "$packdir"/boot

packroot="/tmp/ppgwroot.tar"
tar -cf "$packroot" -C "$packdir" ./
rootsha=$(sha256sum $packroot | cut -d ' ' -f 1)
echo "$rootsha" >/src/iso/rootsha.txt
7z a -t7z -m0=lzma2 -mx=9 -mfb=64 -md=32m -ms=on -mhe=on -bsp1 -bso1 -bse1 -y -p"$rootsha" "/src/iso/root.7z" "$packroot"
