
AR:=ar
CC:=gcc

CFLAGS:= -g -O0
CFLAGS += -fPIC

NLOBJ=lightwanRouteMgmt.o lightwanInfMgmt.o  lightwanConfMgmt.o lightwanBasicTools.o\
	ip_route/ipaddress.o ip_route/iproute.o ip_route/iprule.o \
	ip_route/utils.o ip_route/libnetlink.o ip_route/rt_names.o \
    ip_route/rtm_map.o ip_route/inet_proto.o \
	ip_route/ll_addr.o ip_route/ll_map.o ip_route/ll_proto.o ip_route/ll_types.o \
	ip_route/dnet_ntop.o ip_route/dnet_pton.o ip_route/ipx_ntop.o ip_route/ipx_pton.o

all: lib_lightwanRouteMgmt.a

lib_lightwanRouteMgmt.a: $(NLOBJ)
	$(AR) rcs $@ $(NLOBJ)

install:

clean:
	rm -f $(NLOBJ) lib_lightwanRouteMgmt.a
