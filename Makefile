obj-m := blackpill.o
blackpill-y := src/lib.o src/hypervisor/capabilities.o src/hypervisor/hypervisor.o

CC = clang
ARCH ?= x86_64
CORES = $(shell expr $$(nproc) - 1 )

KDIR ?= $(PWD)/linux
MDIR ?= $(PWD)

THIS_FILE := $(lastword $(MAKEFILE_LIST))

SCRIPTS ?= $(PWD)/scripts
VM ?= $(PWD)/vm
INSTALL_MOD_PATH ?= $(VM)/rootfs


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
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_MOD_STRIP=1
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) modules_install INSTALL_MOD_PATH=$(INSTALL_MOD_PATH) INSTALL_MOD_STRIP=1

rust-analyzer:
	@echo "[+] Generating rust-project.json"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) rust-analyzer

clean:
	@echo "[+] Cleaning workspace"
	$(MAKE) LLVM=1 ARCH=$(ARCH) -C $(KDIR) M=$(MDIR) clean
	rm -rf target/
	rm -rf vm/

kdoc:
	@echo "[+] Generating kernel documentation"
	$(MAKE) LLVM=1 -C $(KDIR) rustdoc

open-kdoc:
	xdg-open $(KDIR)/Documentation/output/rust/rustdoc/kernel/index.html

disk:
	@if [ ! -f $(VM)/disk.img ]; then \
		echo "[-] Disk image doesn't exist"; \
		echo "[+] Creating VM image disk"; \
		$(SCRIPTS)/build_image.sh; \
	else \
		echo "[+] Disk image exists"; \
	fi

vm: disk
	@echo "[+] Launching VM with QEMU"
	$(SCRIPTS)/start_vm.sh | tee $(VM)/start_vm.log

