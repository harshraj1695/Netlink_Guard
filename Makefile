.PHONY: all clean kernel userspace load unload

all: kernel userspace

kernel:
	$(MAKE) -C kernel

userspace:
	$(MAKE) -C userspace

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C userspace clean

load: all
	sudo insmod kernel/kguard_lkm.ko || true

unload:
	sudo rmmod kguard_lkm || true
