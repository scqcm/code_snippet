TARGET=hello

LDFLAGS= -I ./include/generated
include ./include/config/auto.conf

obj-y := hello.c
obj-$(CONFIG_MYPRINT) += myprint.c

all:$(TARGET)
$(TARGET):$(obj-y) FORCE
	gcc $(LDFLAGS) -o $@ $(obj-y)
	echo $@
	echo $(obj-y)
defconfig:
	./scripts/conf Kconfig
	./scripts/conf -s Kconfig
menuconfig:
	./scripts/mconf Kconfig
	./scripts/conf -s --syncconfig Kconfig
clean:
	@-rm ./include/config/*
	@-rm ./include/generated/*
	@-rm ./.config
	@-touch ./include/config/auto.conf
	@-rm $(TARGET)

PHONY +=FORCE
FORCE:

.PHONY: $(PHONY)