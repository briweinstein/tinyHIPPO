#!/bin/ash

# The following is a script which expands the filesystem of a OpenWrt in order to install additional packages
# https://openwrt.org/docs/guide-user/additional-software/extroot_configuration

# For this script to properly work, make sure an external storage device (USB drive, etc.) is directly plugged into the router.

# First, download all the necessary packages to partition an external storage device with the ext4 filesystem
opkg update && opkg install block-mount kmod-fs-ext4 kmod-usb-storage kmod-usb-ohci kmod-usb-uhci e2fsprogs fdisk

sleep 5

# Change the root overlay settings for the external storage device
DEVICE="$(sed -n -e "/\s\/overlay\s.*$/s///p" /etc/mtab)"
uci -q delete fstab.rwm
uci set fstab.rwm="mount"
uci set fstab.rwm.device="${DEVICE}"
uci set fstab.rwm.target="/rwm"
uci commit fstab

sleep 5

# See what partitions are on your router
block info

# Format the external device as ext4
mkfs.ext4 /dev/sda1

sleep 5

# Configure /dev/sda1 as the new overlay
DEVICE="/dev/sda1"
eval $(block info "${DEVICE}" | grep -o -e "UUID=\S*")
uci -q delete fstab.overlay
uci set fstab.overlay="mount"
uci set fstab.overlay.uuid="${UUID}"
uci set fstab.overlay.target="/overlay"
uci commit fstab

# Transfer the data from the exisiting overlay to the external storage device
mount /dev/sda1 /mnt
cp -f -a /overlay/. /mnt
umount /mnt

sleep 5

# Reboot the device
echo 'Device will be rebooting in 5 seconds......'
sleep 5
reboot
