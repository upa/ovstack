KERNELSRCDIR = /lib/modules/$(shell uname -r)/build
BUILD_DIR := $(shell pwd)
VERBOSE = 0
c_flags = -DDEBUG

CC = gcc -Wall

obj-m := ovstack.o oveth.o

all:
	make -C $(KERNELSRCDIR) SUBDIRS=$(BUILD_DIR) KBUILD_VERBOSE=$(VERBOSE)  modules

.c.o:
	$(CC) -Iinclude -c $< -o $@

clean:
	rm -f *.o
	rm -f *.ko
	rm -f *.mod.c
	rm -f *~
