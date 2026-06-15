CLANG ?= clang
KDIR ?= /usr/src/linux-headers-5.15.0-177

BPF_SOURCES = ghostlock_ebpf.c
BPF_OBJECTS = $(BPF_SOURCES:.c=.o)

CFLAGS += -g -O2 -Wall
CFLAGS += -target bpf
CFLAGS += -I$(KDIR)/include
CFLAGS += -I$(KDIR)/include/uapi
CFLAGS += -I$(KDIR)/arch/x86/include
CFLAGS += -I$(KDIR)/arch/x86/include/uapi
CFLAGS += -I$(KDIR)/arch/x86/include/generated/uapi
CFLAGS += -I$(KDIR)/arch/x86/include/generated/asm
CFLAGS += -I$(KDIR)/include/asm-generic
CFLAGS += -I$(KDIR)/include/uapi/asm-generic
CFLAGS += -I$(KDIR)/arch/x86/include/asm # Add this for asm/types.h, asm/bitsperlong.h, etc.
CFLAGS += -I$(KDIR)/include/asm # Generic asm include

.PHONY: all clean

all: $(BPF_OBJECTS)

%.o: %.c
	$(CLANG) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(BPF_OBJECTS)
