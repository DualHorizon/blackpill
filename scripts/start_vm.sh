#!/usr/bin/env bash

# Stage 1
# - Install rootkit
# - Start VM

set -euo pipefail

UPPER="$(realpath $(dirname "$0")/..)"
WORKDIR="$UPPER/vm"
DISK="$WORKDIR/disk.img"
ROOTFS_DIR="$WORKDIR/rootfs"

# Check if the disk image exists
if [ ! -f "$DISK" ]; then
    echo "[-] Disk image not found"
    exit 1
fi

echo "[+] Setting up loop device..."
sudo losetup -Pf "$DISK"
LOOP_DEVICE=$(losetup -l | grep -vi "deleted" | grep "$DISK" | awk '{print $1}')
if [ -z "$LOOP_DEVICE" ]; then
    echo "[-] Loop device not found"
    exit 1
fi

echo "[+] Mounting partition..."
mkdir -p "$ROOTFS_DIR"
sudo mount "${LOOP_DEVICE}p1" "$ROOTFS_DIR"
sudo chown -R "$USER:$USER" "$ROOTFS_DIR"

echo "[+] Installing rootkit"
make install

echo "[+] Cleaning up..."
sudo umount "$ROOTFS_DIR"
sudo losetup -d "$LOOP_DEVICE"

echo "[+] Starting VM..."
/usr/bin/qemu-system-x86_64 \
    -nographic \
    -enable-kvm \
    -m 2G \
    -drive file="$DISK",format=raw \
    -nic user,model=rtl8139
