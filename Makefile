obj-m := blackpill.o
blackpill-y := src/lib.o

THIS_FILE := $(lastword $(MAKEFILE_LIST))

KDIR ?= linux/
MDIR ?= $(PWD)
INSTALL_MOD_PATH ?= $(MDIR)/vm/rootfs
ARCH ?= x86_64
CC = clang

CORES = $(shell expr $$(nproc) - 1 )

default:
	@echo "[+] Compiling module"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules

first-time-setup:
	@echo "[+] Configuring kernel"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) x86_64_defconfig rust.config

	$(MAKE) -f $(THIS_FILE) kernel
	$(MAKE) -f $(THIS_FILE) rust-analyzer

kernel:
	@echo "[+] Compiling kernel"
	$(MAKE) LLVM=1 ARCH=$(ARCH) CC=$(CC) -C $(KDIR) -j $(CORES)

install:
	@echo "[+] Installing modules"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules_install INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_MOD_STRIP=1

rust-analyzer:
	@echo "[+] Generating rust-project.json"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) rust-analyzer

clean:
	@echo "[+] Cleaning workspace"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) clean

disk:
	@echo "[+] Creating VM image disk"
	./build_image.sh

vm: disk
	@echo "[+] Launching VM with QEMU"
	./start_vm.sh

