
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

#include "./include/lightwanRouteMgmt.h"
#include "./ip_route/utils.h"

typedef int (*pFunc)(int argc, char **argv);
static char *delim = " ";

struct rtnl_handle rth = { .fd = -1 };

extern int do_ipaddr(int argc, char **argv);
extern int do_iprule(int argc, char **argv);
extern int do_iproute(int argc, char **argv);


static int 
LW_IPOp(
	__in int ArgCnt,
    __in char *ArgStr,
    pFunc   Func
    )
{
    int ret, i;
    char **ArgStrArray = NULL;
    char *saveptr = NULL;
    
    if ((NULL == ArgStr) || (ArgCnt <= 0))
        return -1;
    
    fprintf(stderr,"[%s-%d]""CMD:%s(%d).\n", 
            __FUNCTION__, __LINE__, ArgStr, ArgCnt);
            
    ArgStrArray = (char **)malloc((ArgCnt+1) * sizeof(char *));
    if (NULL == ArgStrArray)
    {
        fprintf(stderr,"[%s-%d]""couldn't malloc memory-ArgStrArray. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    i = 0;
    ArgStrArray[i++] = strtok_r(ArgStr, delim, &saveptr);
    for (; i < ArgCnt; i++)
    {
        printf("%s\n", ArgStrArray[i-1]);
        ArgStrArray[i] = strtok_r(NULL, delim, &saveptr);
        if(NULL == ArgStrArray[i])
            break;
    }

    if (rtnl_open(&rth, 0) < 0)
        goto CommonReturn;
    
    ret = (*Func)(i, ArgStrArray);
    rtnl_close(&rth);

CommonReturn:
    if (NULL != ArgStrArray)
    {
        free(ArgStrArray);
    }
    return ret;
}
/*******************************************************************************
 * NAME:  LW_IPRouteOp
 *
 * DESCRIPTION:
 *      Modify routing table
 *
 * INPUTS:
 *      ArgCnt: argument cnt ,separated by space. 
 *      ArgAtr: argument string
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      ip route replace default nexthop via xxx dev xxx
 *      char argstr[] = "replace default nexthop via 10.1.4.1 dev eno16777736";
 ******************************************************************************/
int 
LW_IPRouteOp(
	__in int ArgCnt,
    __in char *ArgStr
    )
{
    return LW_IPOp(ArgCnt, ArgStr, &do_iproute);
}

/*******************************************************************************
 * NAME:  LW_IPRuleOp
 *
 * DESCRIPTION:
 *      Modify rule table
 *
 * INPUTS:
 *      ArgCnt: argument cnt ,separated by space. 
 *      ArgAtr: argument string
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      ip rule add table 231 prio 1000
 *      char argstriprule[] = "add table 231 prio 1000";
 ******************************************************************************/
int 
LW_IPRuleOp(
	__in int ArgCnt,
    __in char *ArgStr
    )
{
    return LW_IPOp(ArgCnt, ArgStr, &do_iprule);
}

/*******************************************************************************
 * NAME:  LW_IPAddressOp
 *
 * DESCRIPTION:
 *      Modify ip address
 *
 * INPUTS:
 *      ArgCnt: argument cnt ,separated by space. 
 *      ArgAtr: argument string
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      ip rule add table 231 prio 1000
 *      char argstriprule[] = "table 231 prio 1000";
 ******************************************************************************/
int 
LW_IPAddressOp(
	__in int ArgCnt,
    __in char *ArgStr
    )
{
    return LW_IPOp(ArgCnt, ArgStr, &do_ipaddr);
}