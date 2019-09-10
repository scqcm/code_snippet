LIGHTWAN_BUILD  ?= 0
KDIR            ?= /lib/modules/$(shell uname -r)/build
ARCH            ?= $(shell uname -m)
BUILD_DIR       ?= $(PWD)/build

#submodule
ifeq ($(LIGHTWAN_BUILD),1)
PSBC_ROOT       = ${PWD}/../../psbc
else
PSBC_ROOT       = ${PWD}/../psbc
endif
PSBC_INCS       =   -I${PSBC_ROOT}/include          \
                    -I${PSBC_ROOT}/linux-kern       \
                    -I${PSBC_ROOT}/linux-kern/common
#include
EXTRA_CFLAGS    += -I$(PWD)/include/
EXTRA_CFLAGS    += ${PSBC_INCS}

SRC_FILES	=	lw_ipset_main.c \
			lw_ipset_cmd.c \
			lw_ipset_ops.c \
			lw_ipset_dump.c \
			lw_ipset_tries.c \
			lw_ipset_hashidx.c \
			lw_ipset_lpm.c \
			lw_portset_bitmap.c \
			lw_portset_refcnt.c \
			lw_ipset_proc.c \
			lw_ipset_config.c \

OBJ_FILES  = $(addsuffix .o, $(basename $(SRC_FILES)))

obj-m += lwipset.o
lwipset-objs := $(OBJ_FILES)

all:
	@rm -rf build 2>/dev/null
	@mkdir build 2>/dev/null
	@cp -rf Makefile build/
	make -C $(KDIR) M=$(BUILD_DIR) src=$(PWD) ARCH=$(ARCH) modules

clean:
	rm -rf build
	rm -rf *.o* *.ko *.symvers *.mod* .[a-Z]*
#disable undefined warning
ifneq ($(filter %.modpost, $(MAKEFILE_LIST)),)
.DEFAULT_GOAL := skip_modpost
.PHONY: skip_modpost

skip_modpost:
	@echo "MODPOST skipped!"
endif
