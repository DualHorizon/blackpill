#!/usr/bin/env bash

# Stage 0
# - Build Alpine disk image with minimal installation
# - Copy kernel source to disk image
# - Configure GRUB bootloader
# - Automount next stage disk image
# - Autorun `insmod blackpill.ko` from mounted disk image

set -euo pipefail

# General paths
UPPER="$(realpath $(dirname "$0")/..)"
KERNEL_PATH="$UPPER/linux"
KERNEL_RELEASE=$(make -sC "$KERNEL_PATH" kernelversion)
WORKDIR="$UPPER/vm"

# Disk configuration
DISK_IMG="$WORKDIR/disk.img"
DISK_SIZE="450M"
ROOTFS_DIR="$WORKDIR/rootfs"
BOOT_DIR="$ROOTFS_DIR/boot"
LOOP_DEVICE=""

# Check if the kernel source exists and if it is built
if [ ! -d "$KERNEL_PATH" ]; then
    echo "[-] Kernel source not found"
    exit 1
fi

if [ ! -f "$KERNEL_PATH/arch/x86/boot/bzImage" ]; then
    echo "[*] Kernel not built"
    exit
fi

# Check if the vm folder already exists
if [ ! -d "$WORKDIR" ]; then
    echo "[+] VM folder doesn't exist, creating it"
    mkdir -p "$WORKDIR"
fi

# Delete previous disk image if exists
if [ -f "$DISK_IMG" ]; then
    echo "[+] Deleting previous disk image..."
    rm "$DISK_IMG"
fi

echo "[+] Creating disk image..."
truncate -s "$DISK_SIZE" "$DISK_IMG"

echo "[+] Creating partition table..."
/sbin/parted -s "$DISK_IMG" mktable msdos
/sbin/parted -s "$DISK_IMG" mkpart primary ext4 1 "100%"
/sbin/parted -s "$DISK_IMG" set 1 boot on

echo "[+] Setting up loop device..."
sudo losetup -Pf "$DISK_IMG"
LOOP_DEVICE=$(losetup -l | grep -vi "deleted" | grep "$DISK_IMG" | awk '{print $1}')
if [ -z "$LOOP_DEVICE" ]; then
    echo "[-] Loop device not found"
    exit 1
fi

echo "[+] Formatting partition as ext4..."
sudo mkfs.ext4 "${LOOP_DEVICE}p1"

echo "[+] Mounting partition..."
mkdir -p "$ROOTFS_DIR"
sudo mount "${LOOP_DEVICE}p1" "$ROOTFS_DIR"
sudo chown -R "$USER:$USER" "$ROOTFS_DIR"

echo "[+] Installing minimal Alpine Linux..."
sudo systemctl start docker
docker run -it --rm --volume "$ROOTFS_DIR:/rootfs" alpine sh -c '
    apk add openrc util-linux build-base;
    ln -s agetty /etc/init.d/agetty.ttyS0;
    rc-update add agetty.ttyS0 default;
    sed -i "s/_type}/_type} --autologin root/g" /etc/init.d/agetty.ttyS0;
    rc-update add root default;
    echo "root:" | chpasswd;
    rc-update add devfs boot;
    rc-update add procfs boot;
    rc-update add sysfs boot;
    for d in bin etc lib root sbin usr; do tar c "/$d" | tar x -C /rootfs; done;
    for dir in dev proc run sys var; do mkdir -p /rootfs/${dir}; done;
    printf \"#!/sbin/openrc-run\ncommand="/sbin/modprobe"\ncommand_args="blackpill"\n\" > /etc/init.d/blackpill;
    chmod +x /etc/init.d/blackpill;
    rc-update add blackpill default;
'

echo "[+] Copying Kernel source to rootfs..."
mkdir -p "$ROOTFS_DIR/boot/"
sudo cp "$KERNEL_PATH/arch/x86/boot/bzImage" "$ROOTFS_DIR/boot/vmlinuz"

echo "[+] Configuring GRUB..."
mkdir -p "$ROOTFS_DIR/boot/grub"

cat <<EOF | tee "$ROOTFS_DIR/boot/grub/grub.cfg"
set default=0
set timeout=0
serial
terminal_input serial
terminal_output serial
set root=(hd0,1)
menuentry "blackpill" {
    linux /boot/vmlinuz root=/dev/sda1 console=ttyS0 noapic quiet
}
EOF

echo "[+] Installing GRUB in $BOOT_DIR through ${LOOP_DEVICE}p1"
sudo grub-install --directory=/usr/lib/grub/i386-pc --boot-directory="$BOOT_DIR" "$LOOP_DEVICE"

echo "[+] Cleaning up..."
sudo umount "$ROOTFS_DIR"
sudo losetup -d "$LOOP_DEVICE"

echo "[*] Disk image created successfully at $DISK_IMG"
