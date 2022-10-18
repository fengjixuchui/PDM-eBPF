KDIR ?= /lib/modules/$(shell uname -r)/build
CLANG ?= clang
LLC ?= llc
ARCH := $(subst x86_64,x86,$(shell arch))

BIN := pdm_kern.o
CLANG_FLAGS = -I. -I$(KDIR)/arch/$(ARCH)/include \
	-I$(KDIR)/arch/$(ARCH)/include/generated \
	-I$(KDIR)/include \
	-I$(KDIR)/arch/$(ARCH)/include/uapi \
	-I$(KDIR)/include/uapi \
	-include $(KDIR)/include/linux/kconfig.h \
	-D__KERNEL__ -D__BPF_TRACING__ -Wno-unused-value -Wno-pointer-sign \
	-D__TARGET_ARCH_$(ARCH) -Wno-compare-distinct-pointer-types \
	-Wno-gnu-variable-sized-type-not-at-end \
	-Wno-address-of-packed-member -Wno-tautological-compare \
	-O2 -emit-llvm

all: $(BIN)

a.o: pdm_kern.c
	$(CLANG) $(CLANG_FLAGS) -c $< -o - | \
	$(LLC) -march=bpf -mcpu=$(CPU) -filetype=obj -o $@

clean:
	rm -f *.o