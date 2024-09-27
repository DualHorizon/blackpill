#!/usr/bin/env bash

INITRAMFS=busybox/_install
LKM=src/blackpill.ko

# Copy LKM to image (yes to the root dir)
/usr/bin/cp $LKM $INITRAMFS

# Rebuild image
pushd $INITRAMFS || echo "Error: can't cd into $INITRAMFS"
/usr/bin/find . | /usr/bin/cpio -H newc -o | /usr/bin/gzip > ../ramdisk.img
popd || echo "Error: can't go back to precedent folder"

# Launch VM
/usr/bin/qemu-system-x86_64 \
    -nographic \
    -enable-kvm \
    -m 2G \
    -kernel linux/arch/x86_64/boot/bzImage \
    -initrd busybox/ramdisk.img \
    -nic user,model=rtl8139 \
    --append "console=tty0 console=ttyS0"
