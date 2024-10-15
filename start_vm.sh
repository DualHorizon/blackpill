#!/usr/bin/env bash

DISK="$PWD/vm/disk.img"

# Check if the disk image exists
if [ ! -f "$DISK" ]; then
    echo "[-] Disk image not found"
    exit 1
fi

/usr/bin/qemu-system-x86_64 \
    -nographic \
    -enable-kvm \
    -m 2G \
    -drive file="$DISK",format=raw \
    -nic user,model=rtl8139
