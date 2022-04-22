MODULE_NAME := ipt_SNATPBA
MODULE_LIB := libxt_SNATPBA
KERNEL_VERSION := $(shell uname -r)
KERNEL_SRC := /lib/modules/$(KERNEL_VERSION)/build
MODPATH := /lib/modules/$(KERNEL_VERSION)

obj-m=ipt_SNATPBA.o

all: $(MODULE_LIB).so
	make -C $(KERNEL_SRC) M=$(PWD) modules

$(MODULE_LIB).so: $(MODULE_LIB).o
	$(CC) -shared -fPIC -o $@ $<

$(MODULE_LIB).o: $(MODULE_LIB).c
	$(CC) $(CFLAGS) -Wall -pipe -DPIC -fPIC -g -O2 -o $@ -c $<

clean:
	make -C $(MODPATH)/build/ M=$(PWD) clean
	rm -f $(MODULE_LIB).so

install:
#	install -D -t $(MODPATH)/extra $(MODULE_NAME).ko
	install -D -t $(MODPATH)/kernel/net/netfilter $(MODULE_NAME).ko
	install -D -t $(shell pkg-config xtables --variable xtlibdir) $(MODULE_LIB).so
