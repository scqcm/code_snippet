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
                    -I${PSBC_ROOT}/linux-uspace      \
                    -I${PSBC_ROOT}/linux-uspace/common
#include
CFLAGS    += -I$(PWD)/include/
CFLAGS    += ${PSBC_INCS}

SRC_FILES	=	lw_ipset_main.c \
			lw_ipset_cmd.c \
			lw_ipset_ops.c \
			lw_ipset_dump.c \
			lw_ipset_tries.c \
			lw_ipset_hashidx.c \
			lw_ipset_lpm.c \
			lw_portset_bitmap.c \
			lw_portset_refcnt.c \
			lw_ipset_config.c \

OBJ_FILES  = $(addsuffix .o, $(basename $(SRC_FILES)))
BUILD_FILES  = $(addprefix build/, $(OBJ_FILES))

.PHONY: mkBuild clean

all: lwipset.a

%.o: %.c
	@echo "CC $< -> $@"
	$(CC) $<  ${CFLAGS} -c -o build/$@

lwipset.a: mkBuild $(OBJ_FILES)
	@echo "AR $@" 
	@$(AR) rcs  build/$@ $(BUILD_FILES)
mkBuild:
	@rm -rf build 2>/dev/null
	@mkdir build 2>/dev/null

clean:
	rm -rf build
	rm -rf *.o* *.ko *.symvers *.mod* .[a-Z]*
