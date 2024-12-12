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
echo "[+] Loop device: $LOOP_DEVICE"

# Cleanup function to unmount and detach loop device
cleanup() {
    echo "[+] Cleaning up..."
    if mountpoint -q "$ROOTFS_DIR"; then
        echo "[+] Unmounting $ROOTFS_DIR from $LOOP_DEVICE"
        sudo umount "$ROOTFS_DIR"
    fi
    if losetup -l | grep -q "$LOOP_DEVICE"; then
        echo "[+] Detaching loop device $LOOP_DEVICE"
        sudo losetup -d "$LOOP_DEVICE"
    fi
}
trap cleanup EXIT

echo "[+] Mounting partition..."
mkdir -p "$ROOTFS_DIR"
sudo mount "${LOOP_DEVICE}p1" "$ROOTFS_DIR"
if ! sudo chown -R "$USER:$USER" "$ROOTFS_DIR"; then
    echo "[-] Failed to change ownership of $ROOTFS_DIR (error code: $?)"
    exit 1
fi

echo "[+] Installing rootkit"
if ! make install; then
    echo "[-] Failed to install rootkit (error code: $?)"
    exit 1
fi

ls $ROOTFS_DIR/lib/modules

echo "[+] Starting VM..."
/usr/bin/qemu-system-x86_64 \
    -nographic \
    -enable-kvm \
    -m 2G \
    -drive file="$DISK",format=raw \
    -nic user,model=rtl8139 \
    -cpu host
