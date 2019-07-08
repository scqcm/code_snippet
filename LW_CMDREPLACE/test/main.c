
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>
#include <limits.h>
#include <time.h>

#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <net/if.h>

#include "../include/lightwanRouteMgmt.h"
#include "../include/lightwanInfMgmt.h"
#include "../include/lightwanConfMgmt.h"
#include "../include/lightwanBasicTools.h"

int
main(void)
{
    int i, ret;

	char cmd_addrReplace[][64] ={
		"replace",
        "192.168.110.141/24",
        "dev",
        "eno33554984",
        "broadcast",
		"192.168.110.255"
	};
    

    char cmd_addrDel[][64] ={
		"del",
        "192.168.110.141/24",
        "dev",
        "eno33554984"
	};
    
    char cmd_addrFlush[][64] ={
		"flush",
        "dev",
        "eno33554984"
	};
    
    char cmd_addrShow[][64] ={
		"show",
        "dev",
        "eno33554984"
	};
    
    char cmd_ruleAdd[][64] ={
		"add",
        "prio",
        "47",
        "table",
        "36"
	};
    
    char cmd_ruleDel[][64] ={
		"del",
        "prio",
        "47"
	};
    
    char cmd_routeAdd[][64] ={
		"add",
        "1.2.3.0/24",
        "table",
        "47",
        "proto",
        "static",
        "dev",
        "eno33554984"
	};

    char cmd_routeDel[][64] ={
		"del",
        "1.2.3.0/24",
        "table",
        "47"
	};

    char cmd[][64] ={
		"flush",
        "table",
        "47",
        "dev",
        "eno33554984"
	};
/*	
    int argCnt = sizeof(cmd)/64;
    char *argStr[12];
    for(i = 0; i < argCnt; i++)
    {
        argStr[i] = cmd[i];
    }
    printf("cnt = %d\n", argCnt);
*/

    char argStr[256] ={
		"add "
        "2.2.3.0/24 "
        "table "
        "47 "
        "proto "
        "static "
        "dev "
        "eno33554984"
	};
    
    ret = LW_IPRouteOp(16, argStr);
//    ret = LW_IPRuleOp(argCnt, argStr);
//    ret = LW_IPAddressOp(argCnt, argStr);

/*
    ret = LW_DoEthSet("eno33554984", LW_INFSPEED_UNKNOWN, LW_INFDUPLEX_UNKNOWN, LW_INFAUTONEG_DISABLE);
    printf("ret = %d\n", ret);
    ret = LW_DoEthSet("eno33554984", LW_INFSPEED_100, LW_INFDUPLEX_UNKNOWN, LW_INFAUTONEG_UNKNOWN);
    printf("ret = %d\n", ret);
    ret = LW_DoEthSet("eno33554984", LW_INFSPEED_UNKNOWN, LW_INFDUPLEX_HALF, LW_INFAUTONEG_UNKNOWN);
    printf("ret = %d\n", ret);
    ret = LW_DoEthSet("eno33554984", LW_INFSPEED_UNKNOWN, LW_INFDUPLEX_UNKNOWN, LW_INFAUTONEG_ENABLE);
    printf("ret = %d\n", ret);

    ret = LW_DoSetMtu("eno33554984", 900);
    printf("ret = %d\n", ret);
    ret = LW_DoSetEtherMac("eno33554984", "00:0c:29:e7:56:56");
    printf("ret = %d\n", ret);
    ret = LW_DoIfDown("eno33554984");
    printf("ret = %d\n", ret);
    ret = LW_DoIfUp("eno33554984");
    printf("ret = %d\n", ret);
    ret = LW_AddArpItem("192.168.0.8", "00:0c:29:e7:56:56");
    printf("ret = %d\n", ret);
    ret = LW_DelArpItem("192.168.0.8");
    printf("ret = %d\n", ret);
*/
	return 0;
}