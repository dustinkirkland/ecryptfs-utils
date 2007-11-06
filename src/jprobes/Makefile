obj-m    := jprobe-mount.o
obj-m    += test-jprobe.o
obj-m    += jprobe-create.o
obj-m    += jprobe-release.o

KDIR    := /lib/modules/$(shell uname -r)/build
PWD     := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
clean:
	rm -f *.mod.c *.ko *.o
