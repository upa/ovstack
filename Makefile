KERNELSRCDIR = /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0
c_flags = -DDEBUG

#obj-m := ovstack.o oveth.o
obj-m := ovstack.o dummy.o

all:
	make -C $(KERNELSRCDIR) SUBDIRS=$(BUILD_DIR) KBUILD_VERBOSE=$(VERBOSE)  modules

clean:
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
	rm -f *~
