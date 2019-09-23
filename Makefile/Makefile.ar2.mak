LIB_NAME ?= mactable
STATIC_NAME ?= lib$(LIB_NAME).a
SHARE_NAME  ?= lib$(LIB_NAME).so
BUILD_DIR   ?= $(PWD)/build

SRC_FILES =	mac_admit_table.c
OBJ_FILES = $(addsuffix .o, $(basename $(SRC_FILES)))
BUILD_FILES  = $(addprefix build/, $(OBJ_FILES))

all:$(STATIC_NAME)

%.o: %.c
	@echo "CC $< -> $@"
	$(CC) $<  ${CFLAGS} -fpic -c -o build/$@

mkBuild:
	@rm -rf build 2>/dev/null
	@mkdir build 2>/dev/null
	
$(STATIC_NAME): mkBuild $(OBJ_FILES)
	@echo "AR build/$@" 
	@$(AR) rcs  build/$@ $(BUILD_FILES)
	
$(SHARE_NAME): mkBuild $(OBJ_FILES)
	@echo "$(CC) build/$@" 
	$(CC) ${CFLAGS} -shared -fpic -o $(SHARE_NAME) $(BUILD_FILES);
	
clean:
	rm -rf build
	rm -rf *.o* *.ko *.symvers *.mod* .[a-Z]*