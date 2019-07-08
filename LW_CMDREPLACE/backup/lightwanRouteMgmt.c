/*******************************************************************************
 * LEGALESE:   Copyright (c) 2019 LightWAN Corporation.
 *
 * This source code is confidential, proprietary, and contains trade
 * secrets that are the sole property of LightWAN Corporation.
 * Copy and/or distribution of this source code or disassembly or reverse
 * engineering of the resultant object code are strictly forbidden without
 * the written consent of LightWAN Corporation LLC.
 *
 *******************************************************************************
 * FILE NAME :      lightwanRouteMgmt.h
 *
 * DESCRIPTION :    lightwan route manage module
 *
 * AUTHOR :         sunchao
 *
 * HISTORY :        sunchao     2019/1/28  create
 * Note:
 *       most of the code is excerpted from iproute-3.10.0
 ******************************************************************************/

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

#define NEXT_ARG() do { argv++; if (--argc <= 0) { \
    fprintf(stderr, "Argument line is not complete."); \
    return(-1); } \
    }    while(0)
#define NEXT_ARG_OK() (argc - 1 > 0)
#define PREFIXLEN_SPECIFIED 1

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

typedef struct{
    uint8_t     family;
    uint8_t     bytelen;
    uint16_t    bitlen;
    uint32_t    flags;
    uint32_t    data[8];
} inet_prefix;

struct rtnl_handle{
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    int         fd;
    uint32_t    seq;
    uint32_t    dump;
};

/* rule is permanent, and cannot be deleted */
#define FIB_RULE_PERMANENT      0x00000001
#define FIB_RULE_INVERT         0x00000002
#define FIB_RULE_UNRESOLVED     0x00000004
#define FIB_RULE_IIF_DETACHED   0x00000008
#define FIB_RULE_DEV_DETACHED   FIB_RULE_IIF_DETACHED
#define FIB_RULE_OIF_DETACHED   0x00000010

enum {
    FRA_UNSPEC,
    FRA_DST,    /* destination address */
    FRA_SRC,    /* source address */
    FRA_IIFNAME,    /* interface name */
#define FRA_IFNAME    FRA_IIFNAME
    FRA_GOTO,    /* target to jump to (FR_ACT_GOTO) */
    FRA_UNUSED2,
    FRA_PRIORITY,    /* priority/preference */
    FRA_UNUSED3,
    FRA_UNUSED4,
    FRA_UNUSED5,
    FRA_FWMARK,    /* mark */
    FRA_FLOW,    /* flow/class id */
    FRA_UNUSED6,
    FRA_UNUSED7,
    FRA_UNUSED8,
    FRA_TABLE,    /* Extended table id */
    FRA_FWMASK,    /* mask for netfilter mark */
    FRA_OIFNAME,
    __FRA_MAX
};

#define FRA_MAX (__FRA_MAX - 1)

enum {
    FR_ACT_UNSPEC,
    FR_ACT_TO_TBL,        /* Pass to fixed table */
    FR_ACT_GOTO,        /* Jump to another rule */
    FR_ACT_NOP,            /* No operation */
    FR_ACT_RES3,
    FR_ACT_RES4,
    FR_ACT_BLACKHOLE,    /* Drop without notification */
    FR_ACT_UNREACHABLE,    /* Drop with ENETUNREACH */
    FR_ACT_PROHIBIT,    /* Drop with EACCES */
    __FR_ACT_MAX,
};

#define FR_ACT_MAX (__FR_ACT_MAX - 1)

static int
rtnl_open(
    __in struct rtnl_handle *rth,
    __in uint32_t   subscriptions
    )
{
    socklen_t addr_len;
    int sndbuf = 32768;
    int rcvbuf = 1024 * 1024;

    memset(rth, 0, sizeof(*rth));

    rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rth->fd < 0)
    {
        perror("Cannot open netlink socket");
        return -1;
    }

    if (setsockopt(rth->fd,SOL_SOCKET,SO_SNDBUF,&sndbuf,sizeof(sndbuf)) < 0)
    {
        perror("SO_SNDBUF");
        return -1;
    }

    if (setsockopt(rth->fd,SOL_SOCKET,SO_RCVBUF,&rcvbuf,sizeof(rcvbuf)) < 0) {
        perror("SO_RCVBUF");
        return -1;
    }

    memset(&rth->local, 0, sizeof(rth->local));
    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = subscriptions;

    if (bind(rth->fd, (struct sockaddr*)&rth->local, sizeof(rth->local)) < 0)
    {
        perror("Cannot bind netlink socket");
        return -1;
    }
    addr_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr*)&rth->local, &addr_len) < 0)
    {
        perror("Cannot getsockname");
        return -1;
    }
    if (addr_len != sizeof(rth->local))
    {
        fprintf(stderr, "Wrong address length %d\n", addr_len);
        return -1;
    }
    if (rth->local.nl_family != AF_NETLINK)
    {
        fprintf(stderr, "Wrong address family %d\n", rth->local.nl_family);
        return -1;
    }

    rth->seq = time(NULL);
    return 0;
}

static void
rtnl_close(
    __in struct rtnl_handle *rth
    )
{
    if (rth->fd >= 0)
    {
        close(rth->fd);
        rth->fd = -1;
    }
}

static int
rtnl_talk(
    __in struct rtnl_handle *rtnl,
    __in struct nlmsghdr *n,
    __in pid_t peer,
    __in uint32_t groups,
    __in struct nlmsghdr *answer
    )
{
    int status;
    uint32_t seq;
    struct nlmsghdr *h;
    struct sockaddr_nl nladdr;
    struct iovec iov = {
        .iov_base = (void*) n,
        .iov_len = n->nlmsg_len
    };
    struct msghdr msg = {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    char   buf[16384];

    memset(&nladdr, 0, sizeof(nladdr));
    nladdr.nl_family = AF_NETLINK;
    nladdr.nl_pid = peer;
    nladdr.nl_groups = groups;

    n->nlmsg_seq = seq = ++rtnl->seq;

    if (answer == NULL)
        n->nlmsg_flags |= NLM_F_ACK;

    status = sendmsg(rtnl->fd, &msg, 0);

    if (status < 0)
    {
        perror("Cannot talk to rtnetlink");
        return -1;
    }

    memset(buf,0,sizeof(buf));

    iov.iov_base = buf;

    while (1)
    {
        iov.iov_len = sizeof(buf);
        status = recvmsg(rtnl->fd, &msg, 0);

        if (status < 0)
        {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            fprintf(stderr, "netlink receive error %s (%d)\n",
                strerror(errno), errno);
            return -1;
        }
        if (status == 0)
        {
            fprintf(stderr, "EOF on netlink\n");
            return -1;
        }
        if (msg.msg_namelen != sizeof(nladdr))
        {
            fprintf(stderr, "sender address length == %d\n", msg.msg_namelen);
            return -1;
        }
        for (h = (struct nlmsghdr*)buf; status >= sizeof(*h); )
        {
            int len = h->nlmsg_len;
            int l = len - sizeof(*h);

            if (l < 0 || len>status)
            {
                if (msg.msg_flags & MSG_TRUNC)
                {
                    fprintf(stderr, "Truncated message\n");
                    return -1;
                }
                fprintf(stderr, "!!!malformed message: len=%d\n", len);
                return -1;
            }

            if (nladdr.nl_pid != peer ||
                h->nlmsg_pid != rtnl->local.nl_pid ||
                h->nlmsg_seq != seq)
            {
                /* Don't forget to skip that message. */
                status -= NLMSG_ALIGN(len);
                h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
                continue;
            }

            if (h->nlmsg_type == NLMSG_ERROR)
            {
                struct nlmsgerr *err = (struct nlmsgerr*)NLMSG_DATA(h);
                if (l < sizeof(struct nlmsgerr))
                {
                    fprintf(stderr, "ERROR truncated\n");
                } else
                {
                    if (!err->error)
                    {
                        if (answer)
                            memcpy(answer, h, h->nlmsg_len);
                        return 0;
                    }

                    fprintf(stderr, "RTNETLINK answers: %s\n", strerror(-err->error));
                    errno = -err->error;
                }
                return -1;
            }
            if (answer)
            {
                memcpy(answer, h, h->nlmsg_len);
                return 0;
            }

            fprintf(stderr, "Unexpected reply!!!\n");

            status -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr*)((char*)h + NLMSG_ALIGN(len));
        }
        if (msg.msg_flags & MSG_TRUNC)
        {
            fprintf(stderr, "Message truncated\n");
            continue;
        }
        if (status) {
            fprintf(stderr, "!!!Remnant of size %d\n", status);
            return -1;
        }
    }
}

static int
matches(
    __in const char *cmd,
    __in const char *pattern
    )
{
    int len = strlen(cmd);
    if (len > strlen(pattern))
        return -1;

    return memcmp(pattern, cmd, len);
}

static uint32_t
ll_name_to_index(
    __in const char *name
    )
{
    uint32_t idx;

    if (name == NULL)
        return 0;

    idx = if_nametoindex(name);
    if (idx == 0)
        sscanf(name, "if%u", &idx);

    return idx;
}

static int
addattr_l(
    __inout struct nlmsghdr *n,
    __in int maxlen,
    __in int type,
    __in const void *data,
    __in int alen
    )
{
    int len = RTA_LENGTH(alen);
    struct rtattr *rta = NULL;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen)
    {
        fprintf(stderr, "addattr_l ERROR: message exceeded bound of %d\n",maxlen);
        return -1;
    }
    rta = NLMSG_TAIL(n);
    rta->rta_type = type;
    rta->rta_len = len;
    memcpy(RTA_DATA(rta), data, alen);
    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

    return 0;
}

static int
rta_addattr_l(
    __inout struct rtattr *rta,
    __in int maxlen,
    __in int type,
    __in const void *data,
    __in int alen
    )
{
    struct rtattr *subrta;
    int len = RTA_LENGTH(alen);

    if (RTA_ALIGN(rta->rta_len) + RTA_ALIGN(len) > maxlen)
    {
        fprintf(stderr,"rta_addattr_l: Error! max allowed bound %d exceeded\n",maxlen);
        return -1;
    }
    subrta = (struct rtattr*)(((char*)rta) + RTA_ALIGN(rta->rta_len));
    subrta->rta_type = type;
    subrta->rta_len = len;
    memcpy(RTA_DATA(subrta), data, alen);
    rta->rta_len = NLMSG_ALIGN(rta->rta_len) + RTA_ALIGN(len);
    return 0;
}

static int
get_addr_ipv4(
    __inout uint8_t *ap,
    __in const char *cp
    )
{
    int i = 0;

    for (i = 0; i < 4; i++)
    {
        unsigned long n;
        char *endp;

        n = strtoul(cp, &endp, 0);
        if (n > 255)
            return -1;    /* bogus network value */

        if (endp == cp) /* no digits */
            return -1;

        ap[i] = n;

        if (*endp == '\0')
            break;

        if (i == 3 || *endp != '.')
            return -1;     /* extra characters */
        cp = endp + 1;
    }

    return 1;
}

static int
get_addr(
    __out inet_prefix *addr,
    __in const char *name,
    __in int family
    )
{
    int ret = 0;
    memset(addr, 0, sizeof(*addr));

    if (strcmp(name, "default") == 0 ||
        strcmp(name, "all") == 0 ||
        strcmp(name, "any") == 0)
    {
        addr->family = family;
        addr->bytelen = (family == AF_INET6 ? 16 : 4);
        addr->bitlen = -1;
        ret = 0;
        goto CommonReturn;
    }

    if (strchr(name, ':'))
    {
        addr->family = AF_INET6;
        if (family != AF_UNSPEC && family != AF_INET6)
        {
            ret = -1;
            goto CommonReturn;
        }
        if (inet_pton(AF_INET6, name, addr->data) <= 0)
        {
            ret = -1;
            goto CommonReturn;
        }
        addr->bytelen = 16;
        addr->bitlen = -1;
        {
            ret = 0;
            goto CommonReturn;
        }
    }

    addr->family = AF_INET;
    if (family != AF_UNSPEC && family != AF_INET)
    {
        ret = -1;
        goto CommonReturn;
    }

    if (get_addr_ipv4((uint8_t *)addr->data, name) <= 0)
    {
        ret = -1;
        goto CommonReturn;
    }

    addr->bytelen = 4;
    addr->bitlen = -1;
    ret = 0;

CommonReturn:
    if (-1 == ret)
        fprintf(stderr, "Error: an inet address is expected rather than \"%s\".\n", name);

    return ret;
}

static int
get_unsigned(
    __out unsigned *val,
    __in const char *arg,
    __in int base
    )
{
    unsigned long res;
    char *ptr;

    if (!arg || !*arg)
        return -1;

    res = strtoul(arg, &ptr, base);

    /* empty string or trailing non-digits */
    if (!ptr || ptr == arg || *ptr)
        return -1;

    /* overflow */
    if (res == ULONG_MAX && errno == ERANGE)
        return -1;

    /* out side range of unsigned */
    if (res > UINT_MAX)
        return -1;

    *val = res;
    return 0;
}

static int
get_u32(
    __out uint32_t *val,
    __in const char *arg,
    __in int base
    )
{
    uint32_t res;
    char *ptr;

    if (!arg || !*arg)
        return -1;
    res = strtoul(arg, &ptr, base);

    /* empty string or trailing non-digits */
    if (!ptr || ptr == arg || *ptr)
        return -1;

    /* overflow */
    if (res == ULONG_MAX && errno == ERANGE)
        return -1;

    /* in case UL > 32 bits */
    if (res > 0xFFFFFFFFUL)
        return -1;

    *val = res;
    return 0;
}

static int
mask2bits(
    __in uint32_t netmask
    )
{
    unsigned bits = 0;
    uint32_t mask = ntohl(netmask);
    uint32_t host = ~mask;

    /* a valid netmask must be 2^n - 1 */
    if ((host & (host + 1)) != 0)
        return -1;

    for (; mask; mask <<= 1)
        ++bits;
    return bits;
}

static int
get_netmask(
    __out uint32_t *val,
    __in const char *arg,
    __in int base
    )
{
    inet_prefix addr;

    if (!get_unsigned(val, arg, base))
        return 0;

    /* try coverting dotted quad to CIDR */
    if (!get_addr(&addr, arg, AF_INET) && addr.family == AF_INET) {
        int b = mask2bits(addr.data[0]);

        if (b >= 0) {
            *val = b;
            return 0;
        }
    }

    return -1;
}


static int
get_prefix(
    __out inet_prefix *dst,
    __in char *arg,
    __in int family
    )
{

    int ret;
    uint32_t plen;
    char *slash = NULL;

    memset(dst, 0, sizeof(*dst));

    if (strcmp(arg, "default") == 0 ||
        strcmp(arg, "any") == 0 ||
        strcmp(arg, "all") == 0)
    {
        dst->family = family;
        dst->bytelen = 0;
        dst->bitlen = 0;
        return 0;
    }

    slash = strchr(arg, '/');
    if (slash)
        *slash = 0;

    ret = get_addr(dst, arg, family);
    if (ret == 0)
    {
        switch(dst->family) {
            case AF_INET6:
                dst->bitlen = 128;
                break;
            default:
            case AF_INET:
                dst->bitlen = 32;
        }
        if (slash)
        {
            if (get_netmask(&plen, slash+1, 0)
                || plen > dst->bitlen)
            {
                ret = -1;
                goto CommonReturn;
            }
            dst->flags |= PREFIXLEN_SPECIFIED;
            dst->bitlen = plen;
        }
    }

CommonReturn:
    if (NULL != slash)
        *slash = '/';

    if (-1 == ret)
        fprintf(stderr, "Error: an inet prefix is expected rather than \"%s\".\n", arg);

    return ret;
}

static int
rtnl_rtntype_a2n(
    __out int *id,
    __in char *arg
    )
{
    char *end;
    unsigned long res;

    if (strcmp(arg, "local") == 0)
        res = RTN_LOCAL;
    else if (strcmp(arg, "nat") == 0)
        res = RTN_NAT;
    else if (matches(arg, "broadcast") == 0 ||
         strcmp(arg, "brd") == 0)
        res = RTN_BROADCAST;
    else if (matches(arg, "anycast") == 0)
        res = RTN_ANYCAST;
    else if (matches(arg, "multicast") == 0)
        res = RTN_MULTICAST;
    else if (matches(arg, "prohibit") == 0)
        res = RTN_PROHIBIT;
    else if (matches(arg, "unreachable") == 0)
        res = RTN_UNREACHABLE;
    else if (matches(arg, "blackhole") == 0)
        res = RTN_BLACKHOLE;
    else if (matches(arg, "xresolve") == 0)
        res = RTN_XRESOLVE;
    else if (matches(arg, "unicast") == 0)
        res = RTN_UNICAST;
    else if (strcmp(arg, "throw") == 0)
        res = RTN_THROW;
    else
    {
        res = strtoul(arg, &end, 0);
        if (!end || end == arg || *end || res > 255)
            return -1;
    }
    *id = res;
    return 0;
}

static int
parse_one_nh(
    __inout struct rtmsg *r,
    __inout struct rtattr *rta,
    __inout struct rtnexthop *rtnh,
    __inout int *argcp,
    __inout char ***argvp
)
{
    int argc = *argcp;
    char **argv = *argvp;

    while (++argv, --argc > 0)
    {
        if (strcmp(*argv, "via") == 0)
        {
            inet_prefix addr;
            NEXT_ARG();
            get_addr(&addr, *argv, r->rtm_family);
            if (r->rtm_family == AF_UNSPEC)
                r->rtm_family = addr.family;
            rta_addattr_l(rta, 4096, RTA_GATEWAY, &addr.data, addr.bytelen);
            rtnh->rtnh_len += sizeof(struct rtattr) + addr.bytelen;
        }
        else if (strcmp(*argv, "dev") == 0)
        {
            NEXT_ARG();
            if ((rtnh->rtnh_ifindex = ll_name_to_index(*argv)) == 0)
            {
                fprintf(stderr, "Cannot find device \"%s\"\n", *argv);
                return -1;
            }
        }
        else if (strcmp(*argv, "weight") == 0)
        {
            unsigned w;
            NEXT_ARG();
            if (get_unsigned(&w, *argv, 0) || w == 0 || w > 256)
            {
                fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                    *argv, "\"weight\" is invalid\n");
                return -1;
            }
            rtnh->rtnh_hops = w - 1;
        }
        else if (strcmp(*argv, "onlink") == 0)
        {
            rtnh->rtnh_flags |= RTNH_F_ONLINK;
        } else
            break;
    }
    *argcp = argc;
    *argvp = argv;
    return 0;
}

static int
parse_nexthops(
    __inout struct nlmsghdr *n,
    __inout struct rtmsg *r,
    __in int argc,
    __in char **argv
    )
{
    int ret;
    char buf[1024];
    struct rtattr *rta = (void*)buf;
    struct rtnexthop *rtnh;

    rta->rta_type = RTA_MULTIPATH;
    rta->rta_len = RTA_LENGTH(0);
    rtnh = RTA_DATA(rta);

    while (argc > 0)
    {
        if (strcmp(*argv, "nexthop") != 0)
        {
            fprintf(stderr, "Error: \"nexthop\" or end of line is expected instead of \"%s\"\n", *argv);
            return -1;
        }
        if (argc <= 1)
        {
            fprintf(stderr, "Error: unexpected end of line after \"nexthop\"\n");
            return -1;
        }
        memset(rtnh, 0, sizeof(*rtnh));
        rtnh->rtnh_len = sizeof(*rtnh);
        rta->rta_len += rtnh->rtnh_len;
        ret = parse_one_nh(r, rta, rtnh, &argc, &argv);
        if(ret != 0)
            return ret;
        rtnh = RTNH_NEXT(rtnh);
    }

    if (rta->rta_len > RTA_LENGTH(0))
        addattr_l(n, 1024, RTA_MULTIPATH, RTA_DATA(rta), RTA_PAYLOAD(rta));
    return 0;
}

/*******************************************************************************
 * NAME:  iproute_op
 *
 * DESCRIPTION:
 *      Modify routing table
 *
 * INPUTS:
 *      optype: Operation type
 *      argstr: argument string
 *      arglen: length of argstr, including '\0'
 * RETURN:
 *     !0    failed
 *      0   succeed
 ******************************************************************************/
static int iproute_modify(int cmd, uint16_t flags, int argc,
    char **argv, struct rtnl_handle *rth);
int
LW_IPRouteOp(
    __in LW_IPROUTE_OPTYPE OpType,
    __in char *ArgStr,
    __in int ArgLen
    )
{
    int ret, i, argc = 0;
    char *argv[32];
    char *p;
    struct rtnl_handle rth = { .fd = -1 };

    if((OpType >= LW_IPROUTE_MAX) || (NULL == ArgStr) || (ArgLen <= 0))
        return -1;

    p = ArgStr;
    p[ArgLen-1] = '\0';

    for(i=0; i<32; i++)
    {
        while (*p == ' ')
        {
            p++;
        }
        argv[argc++] = p;
        p = strchr(p, ' ');
        if(NULL == p)
        {
            break;
        }
        else
        {
            *p = '\0';
            p++;
        }
    }

    if (rtnl_open(&rth, 0) < 0)
        return -1;
    switch(OpType) {
        case(LW_IPROUTE_ADD):
            ret = iproute_modify(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_EXCL, argc, argv, &rth);
            break;
        case(LW_IPROUTE_DEL):
            ret = iproute_modify(RTM_DELROUTE, 0, argc, argv, &rth);
            break;
        case(LW_IPROUTE_REPLACE):
            ret = iproute_modify(RTM_NEWROUTE, NLM_F_CREATE|NLM_F_REPLACE, argc, argv, &rth);
            break;
        default:
            ret = -1;
            break;
    }

    rtnl_close(&rth);
    return ret;
}

static int
iproute_modify(
    __in int cmd,
    __in uint16_t flags,
    __in int argc,
    __in char **argv,
    struct rtnl_handle *rth
    )
{
    struct {
        struct nlmsghdr n;
        struct rtmsg    r;
        char    buf[1024];
    } req;
    char  mxbuf[256];
    struct rtattr * mxrta = (void*)mxbuf;
    char  *d = NULL;
    //int gw_ok = 0;
    int dst_ok = 0;
    int table_ok = 0;
    int nhs_ok = 0;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST|flags;
    req.n.nlmsg_type = cmd;
    req.r.rtm_family = AF_INET;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_scope = RT_SCOPE_NOWHERE;

    if (cmd != RTM_DELROUTE)
    {
        req.r.rtm_protocol = RTPROT_BOOT;
        req.r.rtm_scope = RT_SCOPE_UNIVERSE;
        req.r.rtm_type = RTN_UNICAST;
    }

    mxrta->rta_type = RTA_METRICS;
    mxrta->rta_len = RTA_LENGTH(0);

    while (argc > 0)
    {
        if (strcmp(*argv, "src") == 0)
        {
            inet_prefix addr;
            NEXT_ARG();
            get_addr(&addr, *argv, req.r.rtm_family);
            if (req.r.rtm_family == AF_UNSPEC)
                req.r.rtm_family = addr.family;
            addattr_l(&req.n, sizeof(req), RTA_PREFSRC, &addr.data, addr.bytelen);
        }
        else if (strcmp(*argv, "via") == 0)
        {
            inet_prefix addr;
            //gw_ok = 1;
            NEXT_ARG();
            get_addr(&addr, *argv, req.r.rtm_family);
            if (req.r.rtm_family == AF_UNSPEC)
                req.r.rtm_family = addr.family;
            addattr_l(&req.n, sizeof(req), RTA_GATEWAY, &addr.data, addr.bytelen);
        }
        else if (strcmp(*argv, "from") == 0)
        {
            inet_prefix addr;
            NEXT_ARG();
            get_prefix(&addr, *argv, req.r.rtm_family);
            if (req.r.rtm_family == AF_UNSPEC)
                req.r.rtm_family = addr.family;
            if (addr.bytelen)
                addattr_l(&req.n, sizeof(req), RTA_SRC, &addr.data, addr.bytelen);
            req.r.rtm_src_len = addr.bitlen;
        }
        else if (strcmp(*argv, "nexthop") == 0)
        {
            nhs_ok = 1;
            break;
        }
        else if (matches(*argv, "table") == 0)
        {
            uint32_t tid;
            char *end;
            NEXT_ARG();
            tid = strtoul(*argv, &end, 0);
            if (!end || end == *argv || *end || tid > RT_TABLE_MAX)
            {
                fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                    *argv, "\"table\" value is invalid\n");
                return -1;
            }
            if (tid < 256)
                req.r.rtm_table = tid;
            else {
                req.r.rtm_table = RT_TABLE_UNSPEC;
                addattr_l(&req.n, sizeof(req), RTA_TABLE, &tid, sizeof(uint32_t));
            }
            table_ok = 1;
        }
        else if (strcmp(*argv, "dev") == 0 || strcmp(*argv, "oif") == 0)
        {
            NEXT_ARG();
            d = *argv;
        }
        else
        {
            int type;
            inet_prefix dst;

            if (strcmp(*argv, "to") == 0)
            {
                NEXT_ARG();
            }
            if ((**argv < '0' || **argv > '9') &&
                rtnl_rtntype_a2n(&type, *argv) == 0)
            {
                NEXT_ARG();
                req.r.rtm_type = type;
            }

            if (dst_ok)
            {
                fprintf(stderr, "Error: either \"%s\" is duplicate, or \"%s\" is a garbage.\n", "to", *argv);
                return -1;
            }
            get_prefix(&dst, *argv, req.r.rtm_family);
            if (req.r.rtm_family == AF_UNSPEC)
                req.r.rtm_family = dst.family;
            req.r.rtm_dst_len = dst.bitlen;
            dst_ok = 1;
            if (dst.bytelen)
                addattr_l(&req.n, sizeof(req), RTA_DST, &dst.data, dst.bytelen);
        }
        argc--; argv++;
    }

    if (d || nhs_ok)
    {
        int idx;

        if (d)
        {
            if ((idx = ll_name_to_index(d)) == 0)
            {
                fprintf(stderr, "Cannot find device \"%s\"\n", d);
                return -1;
            }
            addattr_l(&req.n, sizeof(req), RTA_OIF, &idx, sizeof(uint32_t));
        }
    }

    if (mxrta->rta_len > RTA_LENGTH(0))
    {
        addattr_l(&req.n, sizeof(req), RTA_METRICS, RTA_DATA(mxrta), RTA_PAYLOAD(mxrta));
    }

    if (nhs_ok)
        parse_nexthops(&req.n, &req.r, argc, argv);

    if (!table_ok)
    {
        if (req.r.rtm_type == RTN_LOCAL ||
            req.r.rtm_type == RTN_BROADCAST ||
            req.r.rtm_type == RTN_NAT ||
            req.r.rtm_type == RTN_ANYCAST)
            req.r.rtm_table = RT_TABLE_LOCAL;
    }

    if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0)
        return -1;//exit(2);

    return 0;
}

/*******************************************************************************
 * NAME:  iprule_op
 *
 * DESCRIPTION:
 *      Modify routing table
 *
 * INPUTS:
 *      optype: Operation type
 *      argstr: argument string
 *      arglen: length of argstr, including '\0'
 * RETURN:
 *     !0    failed
 *      0   succeed
 ******************************************************************************/
static int iprule_modify(int cmd, int argc, char **argv, struct rtnl_handle *rth);
int
LW_IPRuleOp(
    __in LW_IPRULE_OPTYPE OpType,
    __in char *ArgStr,
    __in int ArgLen
    )
{
    int ret, i, argc = 0;
    char *argv[32];
    char *p;
    struct rtnl_handle rth = { .fd = -1 };

    if((OpType >= LW_IPRULE_MAX) || (NULL == ArgStr) || (ArgLen <= 0))
        return -1;

    p = ArgStr;
    p[ArgLen-1] = '\0';

    for(i=0; i<32; i++)
    {
        while (*p == ' ')
        {
            p++;
        }
        argv[argc++] = p;
        p = strchr(p, ' ');
        if(NULL == p)
        {
            break;
        }
        else
        {
            *p = '\0';
            p++;
        }
    }

    if (rtnl_open(&rth, 0) < 0)
        return -1;
    switch(OpType) {
        case(LW_IPRULE_ADD):
            ret = iprule_modify(RTM_NEWRULE, argc, argv, &rth);
            break;
        case(LW_IPRULE_DEL):
            ret = iprule_modify(RTM_DELRULE, argc, argv, &rth);
            break;
        default:
            ret = -1;
            break;
    }

    rtnl_close(&rth);
    return ret;
}

int
iprule_modify(
    int cmd,
    int argc,
    char **argv,
    struct rtnl_handle *rth
    )
{
    int table_ok = 0;
    struct {
        struct nlmsghdr     n;
        struct rtmsg         r;
        char               buf[1024];
    } req;

    memset(&req, 0, sizeof(req));

    req.n.nlmsg_type = cmd;
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.r.rtm_family = AF_INET;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_table = 0;
    req.r.rtm_type = RTN_UNSPEC;
    req.r.rtm_flags = 0;

    if (cmd == RTM_NEWRULE)
    {
        req.n.nlmsg_flags |= NLM_F_CREATE|NLM_F_EXCL;
        req.r.rtm_type = RTN_UNICAST;
    }

    while (argc > 0)
    {
        if (strcmp(*argv, "not") == 0)
        {
            req.r.rtm_flags |= FIB_RULE_INVERT;
        }
        else if (strcmp(*argv, "from") == 0)
        {
            inet_prefix dst;
            NEXT_ARG();
            get_prefix(&dst, *argv, req.r.rtm_family);
            req.r.rtm_src_len = dst.bitlen;
            addattr_l(&req.n, sizeof(req), FRA_SRC, &dst.data, dst.bytelen);
        }
        else if (strcmp(*argv, "to") == 0)
        {
            inet_prefix dst;
            NEXT_ARG();
            get_prefix(&dst, *argv, req.r.rtm_family);
            req.r.rtm_dst_len = dst.bitlen;
            addattr_l(&req.n, sizeof(req), FRA_DST, &dst.data, dst.bytelen);
        }
        else if (matches(*argv, "preference") == 0 ||
               matches(*argv, "order") == 0 ||
               matches(*argv, "priority") == 0)
        {
            uint32_t pref;
            NEXT_ARG();
            if (get_u32(&pref, *argv, 0))
            {
                fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                    *argv, "preference value is invalid\n");
                return -1;
            }
            addattr_l(&req.n, sizeof(req), FRA_PRIORITY, &pref, sizeof(uint32_t));
        }
        else if (matches(*argv, "table") == 0 ||
            strcmp(*argv, "lookup") == 0)
        {
            uint32_t tid;
            char *end;
            NEXT_ARG();
            tid = strtoul(*argv, &end, 0);
            if (!end || end == *argv || *end || tid > RT_TABLE_MAX)
            {
                fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                    *argv, "invalid table ID\n");
                return -1;
            }
            if (tid < 256)
                req.r.rtm_table = tid;
            else
            {
                req.r.rtm_table = RT_TABLE_UNSPEC;
                addattr_l(&req.n, sizeof(req), FRA_TABLE, &tid, sizeof(uint32_t));
            }
            table_ok = 1;
        }
        else
        {
            int type;

            if (strcmp(*argv, "type") == 0)
            {
                NEXT_ARG();
            }
            else if (matches(*argv, "goto") == 0)
            {
                uint32_t target;
                type = FR_ACT_GOTO;
                NEXT_ARG();
                if (get_u32(&target, *argv, 0))
                {
                    fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                        *argv, "invalid target\n");
                    return -1;
                }
                addattr_l(&req.n, sizeof(req), FRA_GOTO, &target, sizeof(uint32_t));
            }
            else if (matches(*argv, "nop") == 0)
                type = FR_ACT_NOP;
            else if (rtnl_rtntype_a2n(&type, *argv))
            {
                fprintf(stderr, "Error: argument \"%s\" is wrong: %s\n",
                    *argv, "Failed to parse rule type");
                return -1;
            }
            req.r.rtm_type = type;
            table_ok = 1;
        }
        argc--;
        argv++;
    }

    if (req.r.rtm_family == AF_UNSPEC)
        req.r.rtm_family = AF_INET;

    if (!table_ok && cmd == RTM_NEWRULE)
        req.r.rtm_table = RT_TABLE_MAIN;

    if (rtnl_talk(rth, &req.n, 0, 0, NULL) < 0)
    {
        fprintf(stderr, "Error: rtnl_talk is fail.\n");
        return -1;
    }

    return 0;
}