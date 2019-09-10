
$(info "here add the debug info")
LIGHTWAN_BUILD  ?= "-g -O3 -D"
$(info $(LIGHTWAN_BUILD) )
$(warning "here add the debug info")
#$(error "error: this will stop the compile")
LIGHTWAN_BUILD_1 := $(patsubst -O3,-O0,$(LIGHTWAN_BUILD) )
LIGHTWAN_BUILD := $(LIGHTWAN_BUILD_1)

all:
	touch a
	rm a
	@echo $(subst t,e,maktfilt)
	@echo $(patsubst %.c,%.o,programA.c programB.c)
	@echo $(LIGHTWAN_BUILD)
    $(warning $(origin LIGHTWAN_BUILD))
    $(warning $(origin ifeq))
    $(warning $(origin VERSION))
    
