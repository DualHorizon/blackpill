KDIR = linux/
SRC = src/

default:
	$(MAKE) LLVM=1 CLIPPY=1 -j $(nproc) -C $(KDIR) M=$$PWD

vm:
	./testvm.sh
