KDIR ?= /lib/modules/$(shell uname -r)/build
all: .exfat.rust.o.cmd
	$(MAKE) -C $(KDIR) KDIR=$(KDIR) M=$(CURDIR)
.exfat.rust.o.cmd:
	touch .exfat.rust.o.cmd
clean:
	$(MAKE) -C $(KDIR) KDIR=$(KDIR) M=$(CURDIR) clean
	cargo clean