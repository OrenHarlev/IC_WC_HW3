KERNEL_SOURCE := /lib/modules/$(shell uname -r)/build
obj-m += firewall.o
firewall-objs := FWLogger.o FWModule.o FWPacketMatcher.o FWPacketParser.o FWRuleManager.o FWConnectionManager.o FWProxyHelper.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean