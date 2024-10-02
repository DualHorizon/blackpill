<h1 align="center">BlackPill</h1>
<p align="center">BlackPill is a stealthy Linux rootkit made in Rust.<p>
<div align="center">
    <img alt="Open issues"     src="https://img.shields.io/github/issues/DualHorizon/blackpill?style=for-the-badge&color=%23973B21&labelColor=%230C1510">
    <img alt="Commit activity" src="https://img.shields.io/github/commit-activity/w/DualHorizon/blackpill?style=for-the-badge&color=%23973B21&labelColor=%230C1510">
    <img alt="License"         src="https://img.shields.io/github/license/DualHorizon/blackpill?style=for-the-badge&color=%23973B21&labelColor=%230C1510">
</div>

## Features

![Rootkit simple architecture schema](assets/blackpill-rootkit-overview.drawio.png)

todo

## Development environment

### Description

Multiple steps needs to be done before compiling our rootkit. The development environment is composed of :
- a simple busybox initramfs providing essential tools
- a custom compiled minimal kernel with Rust activated
- a simple QEMU virtual machine accelerated by KVM

Start by cloning the repository and its submodules :
```shell
$ git clone git@github.com:DualHorizon/blackpill.git --recursive
```

### QEMU

On an arch-based distribution :

```shell
$ sudo pacman -S qemu-base qemu-desktop
```

### Busybox

```shell
$ cd busybox/
$ make defconfig
$ git am ../patches/busybox-ncurses-fix.patch
$ make menuconfig
# Then navigate into "Settings" and select "Build static binary (no shared libs)"
```

You can then compile and create the image :

```shell
$ make -j $(nproc)
$ make install
```

If you have `TC` related errors, run the following command and recompile :

```shell
$ sed -i "s/CONFIG_TC=y/CONFIG_TC=n/g" .config
```

Once done, create the ramdisk image :

```shell
$ cd _install
$ mkdir -p bin sbin etc proc sys dev usr/{s,}bin
$ cp ../examples/inittab ./etc/
$ sed "s/^tty.*//g" etc/inittab
$ cat > "init" <<END
#!/bin/sh

mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev

ifconfig lo up
ifconfig eth0 up
udhcpc -i eth0

/bin/sh
END
$ chmod +x init
$ find . | cpio -H newc -o | gzip > ../ramdisk.img
```

### Linux kernel

On an arch-based Linux distribution :

```shell
$ sudo pacman -S clang lld llvm
```

Then we'll need Rust sources and bindgen :

```shell
$ rustup component add rust-src
$ cargo install --locked bindgen-cli
```

Make sure everything is ok by running in folder `linux/` :

```shell
$ cd linux
$ make LLVM=1 rustavailable
Rust is available!
```

Then apply the patch to create a new minimal kernel config (still in `linux/`):

```shell
$ git am ../patches/qemu-busybox-min.patch
```

We can configure our kernel and build it :

```shell
$ make LLVM=1 allnoconfig qemu-busybox-min.config rust.config
$ make LLVM=1 -j $(nproc)
$ make LLVM=1 -j $(nproc) rust-analyzer
$ cd ..
$ make -C linux/ M=$PWD rust-analyzer
```

### Rootkit

You can compile the Rust kernel module (out-of-tree) with :

```shell
$ make
```

Launch the VM with :

```shell
$ make vm
```

## Usage

todo

## Roadmap

**v0.1.0**

- [ ] To-do

**v0.2.0**

- [ ] To-do

## Credits

Environment setup :
- [Setting Up an Environment for Writing Linux Kernel Modules in Rust - The Linux Foundation](https://www.youtube.com/watch?v=tPs1uRqOnlk)
- [Kernel config qemu-busybox-min.config patch](https://lore.kernel.org/rust-for-linux/20230609063118.24852-18-amiculas@cisco.com/)
- [Rust out-of-tree module](https://github.com/Rust-for-Linux/rust-out-of-tree-module)
