KDIR = linux/
SRC = src/

# Allows our Kbuild to build every rust source automatically
RUST_SOURCES = $(shell find $(SRC) -name '*.rs')
RUST_OBJECTS = $(RUST_SOURCES:.rs=.o)
export RUST_OBJECTS

default:
	$(MAKE) LLVM=1 CLIPPY=1 -j $(nproc) -C $(KDIR) M=$$PWD

vm:
	./testvm.sh
