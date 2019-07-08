
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/sockios.h>
#include <linux/if_ether.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>

#include "include/lightwanInfMgmt.h"

/* CMDs currently supported */
#define ETHTOOL_GSET		0x00000001 /* Get settings. */
#define ETHTOOL_SSET		0x00000002 /* Set settings. */


struct ethtool_cmd {
    uint32_t	cmd;
    uint32_t	supported;      /* Features this interface supports */
    uint32_t	advertising;	/* Features this interface advertises */
    uint16_t	speed;	        /* The forced speed (lower bits) in Mbps. Please use
                                 * ethtool_cmd_speed()/_set() to access it */
    uint8_t     duplex;         /* Duplex, half or full */
    uint8_t     port;           /* Which connector port */
    uint8_t     phy_address;    /* MDIO PHY address (PRTAD for clause 45).
                                 * May be read-only or read-write depending on the driver.*/
    uint8_t     transceiver;    /* Which transceiver to use */
    uint8_t     autoneg;        /* Enable or disable autonegotiation */
    uint8_t     mdio_support;   /* MDIO protocols supported.  Read-only. Not set by all drivers.*/
    uint32_t	maxtxpkt;       /* Tx pkts before generating tx int */
    uint32_t	maxrxpkt;       /* Rx pkts before generating rx int */
    uint16_t	speed_hi;       /* The forced speed (upper bits) in Mbps. Please use
                                 * ethtool_cmd_speed()/_set() to access it */
    uint8_t     eth_tp_mdix;	/* twisted pair MDI-X status */
    uint8_t     eth_tp_mdix_ctrl;   /* twisted pair MDI-X control, when set,
                                     * link should be renegotiated if necessary*/
    uint32_t	lp_advertising; /* Features the link partner advertises */
    uint32_t	reserved[2];
};

/*******************************************************************************
 * NAME:  LW_DoEthSet
 *
 * DESCRIPTION:
 *      control network device driver and hardware settings, 
 *      particularly for wired Ethernet devices.
 *
 * INPUTS:
 *      IfName: Specifies a network device
 *      SpeedWanted: Set speed in Mb/s
 *      DuplexWanted: Sets full or half duplex mode
 *      AutonegWanted: Specifies whether pause autonegotiation should be enabled
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoEthSet(
    __in char *IfName,
    __in int SpeedWanted,
    __in unsigned char DuplexWanted,
    __in unsigned char AutonegWanted
    )
{
    struct ifreq ifr;
    struct ethtool_cmd ecmd;
    int speed_wanted = LW_INFSPEED_UNKNOWN;
	int duplex_wanted = LW_INFDUPLEX_UNKNOWN;
	int autoneg_wanted = LW_INFAUTONEG_UNKNOWN;
    int gset_changed = 0;
    int fd;
    int ret = 0;
    
    if (strlen(IfName) >= IFNAMSIZ)
    {
        fprintf(stderr,"[%s-%d]""ifname(%s) is toolong.\n", 
            __FUNCTION__, __LINE__, IfName);
        return -1;
    }
    memcpy(ifr.ifr_name, IfName, strlen(IfName));
    ifr.ifr_name[strlen(IfName)] = '\0';
    
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        fprintf(stderr,"[%s-%d]""Fail to create socket. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }

    switch (SpeedWanted)
    {
        case LW_INFSPEED_10:
           speed_wanted = LW_INFSPEED_10;
           break;
        case LW_INFSPEED_100:
           speed_wanted = LW_INFSPEED_100;
           break;
        case LW_INFSPEED_1000:
           speed_wanted = LW_INFSPEED_1000;
           break;
        case LW_INFSPEED_2500:
           speed_wanted = LW_INFSPEED_2500;
           break;
        case LW_INFSPEED_10000:
           speed_wanted = LW_INFSPEED_10000;
           break;
    }
    
    switch (DuplexWanted)
    {
        case LW_INFDUPLEX_HALF:
           duplex_wanted = LW_INFDUPLEX_HALF;
           break;
        case LW_INFDUPLEX_FULL:
           duplex_wanted = LW_INFDUPLEX_FULL;
           break;
    }
    
    switch (AutonegWanted)
    {
        case LW_INFAUTONEG_DISABLE:
           autoneg_wanted = LW_INFAUTONEG_DISABLE;
           break;
        case LW_INFAUTONEG_ENABLE:
           autoneg_wanted = LW_INFAUTONEG_ENABLE;
           break;
    }

    ecmd.cmd = ETHTOOL_GSET;
    ifr.ifr_data = (void*)&ecmd;
    ret = ioctl(fd, SIOCETHTOOL, &ifr);
    if (ret < 0) 
    {
        fprintf(stderr,"[%s-%d]""%s: ERROR while getting interface flags. error_string:%s.\n", 
            __FUNCTION__, __LINE__, IfName, strerror(errno));
        return -1;
    }
        
    if (speed_wanted != LW_INFSPEED_UNKNOWN)
    {
        ecmd.speed = (uint16_t)speed_wanted;
        ecmd.speed_hi = (uint16_t)(speed_wanted >> 16);
        gset_changed = 1;
    }
    if (duplex_wanted != LW_INFDUPLEX_UNKNOWN)
    {
        ecmd.duplex = duplex_wanted;
        gset_changed = 1;
    }
    if (autoneg_wanted != LW_INFAUTONEG_UNKNOWN)
    {
        ecmd.autoneg = autoneg_wanted;
        gset_changed = 1;
    }
            
    if (gset_changed) 
    {
        /* Try to perform the update. */
        ecmd.cmd = ETHTOOL_SSET;
        ifr.ifr_data = (void*)&ecmd;
        ret = ioctl(fd, SIOCETHTOOL, &ifr);
        if (ret < 0) 
        {
            fprintf(stderr,"[%s-%d]""%s: ERROR while setting interface flags. error_string:%s.\n", 
                __FUNCTION__, __LINE__, IfName, strerror(errno));
            ret = -1;
        }
        else
        {
            ret = 0;
        }
	}
    else
    {
        fprintf(stderr,"[%s-%d]""%s: Have nothing to do.\n", 
                __FUNCTION__, __LINE__, IfName);
        ret = -1;
    }
    
    return ret;
}


static int skfd = -1;

static int 
set_flag(
    char *ifname, /*strlen(ifname) < IFNAMSIZ*/
    short flag
    )
{
    struct ifreq ifr;

    memcpy(ifr.ifr_name, ifname, strlen(ifname));
    ifr.ifr_name[strlen(ifname)] = '\0';
    if (ioctl(skfd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""%s: ERROR while getting interface flags. error_string:%s.\n", 
            __FUNCTION__, __LINE__, ifname, strerror(errno));
        return (-1);
    }
    
    memcpy(ifr.ifr_name, ifname, strlen(ifname));
    ifr.ifr_name[strlen(ifname)] = '\0';
    ifr.ifr_flags |= flag;
    if (ioctl(skfd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""%s: ERROR while setting interface flags. error_string:%s.\n", 
            __FUNCTION__, __LINE__, ifname, strerror(errno));
        return -1;
    }
    return (0);
}

/* Clear a certain interface flag. */
static int 
clr_flag(
    char *ifname, 
    short flag
    )
{
    struct ifreq ifr;
    int fd;

    if (strchr(ifname, ':')) {
        fprintf(stderr,"[%s-%d]""%s: No support for INET on this system.\n", 
            __FUNCTION__, __LINE__, ifname);
	    return -1;
	}
    fd = skfd;

    memcpy(ifr.ifr_name, ifname, strlen(ifname));
    ifr.ifr_name[strlen(ifname)] = '\0';
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""%s: ERROR while getting interface flags. error_string:%s.\n", 
            __FUNCTION__, __LINE__, ifname, strerror(errno));
        return -1;
    }
    memcpy(ifr.ifr_name, ifname, strlen(ifname));
    ifr.ifr_name[strlen(ifname)] = '\0';
    ifr.ifr_flags &= ~flag;
    if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""%s: ERROR while setting interface flags. error_string:%s.\n", 
            __FUNCTION__, __LINE__, ifname, strerror(errno));
        return -1;
    }
    return (0);
}

/*******************************************************************************
 * NAME:  LW_DoIfUp
 *
 * DESCRIPTION:
 *      activate the interface.
 *
 * INPUTS:
 *      IfName: Specifies a network device
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoIfUp(
    char *IfName
    )
{
    int ret = 0;
    if (strlen(IfName) >= IFNAMSIZ)
    {
        fprintf(stderr,"[%s-%d]""IfName is toolong.\n", 
            __FUNCTION__, __LINE__);
        return -1;
    }
    
    skfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (skfd < 0)
    {
        fprintf(stderr,"[%s-%d]""Fail to create socket. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    ret = set_flag(IfName, (IFF_UP | IFF_RUNNING));
    
    (void) close(skfd);
    return ret;
}

/*******************************************************************************
 * NAME:  LW_DoIfDown
 *
 * DESCRIPTION:
 *      shut down the interface.
 *
 * INPUTS:
 *      IfName: Specifies a network device
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoIfDown(
    char *IfName
    )
{
    int ret = 0;
    if (strlen(IfName) >= IFNAMSIZ)
    {
        fprintf(stderr,"[%s-%d]""IfName is toolong.\n", 
            __FUNCTION__, __LINE__);
        return -1;
    }
    
    skfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (skfd < 0)
    {
        fprintf(stderr,"[%s-%d]""No usable address families found. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    ret = clr_flag(IfName, IFF_UP);
    
    (void) close(skfd);
    return ret;
}

/*******************************************************************************
 * NAME:  LW_DoSetMtu
 *
 * DESCRIPTION:
 *      set the Maximum Transfer Unit (MTU) of an interface.
 *
 * INPUTS:
 *      IfName: Specifies a network device
 *      mtu: the Maximum Transfer Unit
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoSetMtu(
    char *IfName, 
    int mtu
    )
{
    struct ifreq ifr;
    int ret = 0;
    
    if (strlen(IfName) >= IFNAMSIZ)
    {
        fprintf(stderr,"[%s-%d]""IfName is toolong.\n", 
            __FUNCTION__, __LINE__);
        return -1;
    }
    skfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (skfd < 0)
    {
        fprintf(stderr,"[%s-%d]""No usable address families found. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    memcpy(ifr.ifr_name, IfName, strlen(IfName));
    ifr.ifr_name[strlen(IfName)] = '\0';
    ifr.ifr_mtu = mtu;
    if (ioctl(skfd, SIOCSIFMTU, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""SIOCSIFMTU. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        ret = -1;
	}
    
    (void) close(skfd);
    return ret;
}

/*转换MAC地址格式，文本->二级制*/
static int 
in_ether(
    char *bufp, 
    struct sockaddr *sap
    )
{
    char *ptr;
    char c;
    int i;
    unsigned val;

    sap->sa_family = 1;//ARPHRD_ETHER;
    ptr = sap->sa_data;

    i = 0;
    while ((*bufp != '\0') && (i < ETH_ALEN)) 
    {
        val = 0;
        c = *bufp++;
        if (isdigit(c))
            val = c - '0';
        else if (c >= 'a' && c <= 'f')
            val = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val = c - 'A' + 10;
        else {
            errno = EINVAL;
            return (-1);
        }
        val <<= 4;
        c = *bufp;
        if (isdigit(c))
            val |= c - '0';
        else if (c >= 'a' && c <= 'f')
            val |= c - 'a' + 10;
        else if (c >= 'A' && c <= 'F')
            val |= c - 'A' + 10;
        else if (c == ':' || c == 0)
            val >>= 4;
        else {
            errno = EINVAL;
            return (-1);
        }
        if (c != 0)
            bufp++;
        *ptr++ = (unsigned char) (val & 0377);
        i++;

        /* We might get a semicolon here - not required. */
        if (*bufp == ':') {
            bufp++;
        }
    }

    return (0);
}

/*******************************************************************************
 * NAME:  LW_DoSetMac
 *
 * DESCRIPTION:
 *      set the Maximum Transfer Unit (MTU) of an interface.
 *
 * INPUTS:
 *      IfName: Specifies a network device
 *      mtu: the Maximum Transfer Unit
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoSetEtherMac(
    __in char *IfName, 
    __in char *Mac
    )
{
    struct ifreq ifr;
    int ret = 0;
    struct sockaddr_storage _sa;
    struct sockaddr *sa = (struct sockaddr *)&_sa;
    
    if (strlen(IfName) >= IFNAMSIZ)
    {
        fprintf(stderr,"[%s-%d]""IfName is toolong.\n", 
            __FUNCTION__, __LINE__);
        return -1;
    }
    ret = in_ether(Mac, sa);
    if(0 != ret)
    {
        return -1;
    }
    
    skfd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (skfd < 0)
    {
        fprintf(stderr,"[%s-%d]""No usable address families found. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    memcpy(ifr.ifr_name, IfName, strlen(IfName));
    ifr.ifr_name[strlen(IfName)] = '\0';
    memcpy(&ifr.ifr_hwaddr, sa, sizeof(struct sockaddr));
    
    if (ioctl(skfd, SIOCSIFHWADDR, &ifr) < 0) {
        fprintf(stderr,"[%s-%d]""SIOCSIFHWADDR. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        ret = -1;
	}
    
    (void) close(skfd);
    return ret;
}

/*******************************************************************************
 * NAME:  LW_AddArpItem
 *
 * DESCRIPTION:
 *      set up a new arp table entry.
 *
 * INPUTS:
 *      IPAddr: Specifies a network device
 *      EtherAddr: this is 6 bytes in hexadecimal, separated by colons
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_AddArpItem(
    char *IPAddr,
    char *EtherAddr
    )
{
    char host[128];
    struct arpreq req;
    struct sockaddr_storage ss;
    struct sockaddr_in *sa_in;
    int ret;
    char device[16] = "";
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        fprintf(stderr,"[%s-%d]""No usable address families found. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    memset((char *) &req, 0, sizeof(req));
    sa_in = (struct sockaddr_in *)&ss;
    
    sa_in->sin_family = AF_INET;
    sa_in->sin_port = 0;

    /* Default is special, meaning 0.0.0.0. */
    if (!strcmp(IPAddr, "default")) 
    {
        sa_in->sin_addr.s_addr = INADDR_ANY;
    }
    
    /* Look to see if it's a dotted quad. */
    if ( 0 == inet_aton(IPAddr, &sa_in->sin_addr)) 
    {
        return -1;
    }
    memcpy((char *) &req.arp_pa, (char *) sa_in, sizeof(struct sockaddr));
    
    ret = in_ether(EtherAddr, &req.arp_ha);
    if(0 != ret)
    {
        return -1;
    }
    
    /* Fill in the remainder of the request. */
    req.arp_flags = ATF_PERM | ATF_COM;
    memcpy(req.arp_dev, device, sizeof(req.arp_dev));
    
    if (ioctl(fd, SIOCSARP, &req) < 0) {
        fprintf(stderr,"[%s-%d]""SIOCSARP. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
    }

    (void) close(fd);
	return (0);
}

/*******************************************************************************
 * NAME:  LW_DelArpItem
 *
 * DESCRIPTION:
 *      deletel a new arp table entry.
 *
 * INPUTS:
 *      IPAddr: Specifies a network device
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DelArpItem(
    char *IPAddr
    )
{
    struct arpreq req;
    struct sockaddr_storage ss;
    struct sockaddr_in *sa_in;
    //char device[16] = "";
    int fd;

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        fprintf(stderr,"[%s-%d]""No usable address families found. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    
    memset((char *) &req, 0, sizeof(req));
    sa_in = (struct sockaddr_in *)&ss;
    
    sa_in->sin_family = AF_INET;
    sa_in->sin_port = 0;

    /* Default is special, meaning 0.0.0.0. */
    if (!strcmp(IPAddr, "default")) 
    {
        sa_in->sin_addr.s_addr = INADDR_ANY;
    }
    
    /* Look to see if it's a dotted quad. */
    if ( 0 == inet_aton(IPAddr, &sa_in->sin_addr)) 
    {
        return -1;
    }
    
    memcpy((char *) &req.arp_pa, (char *) sa_in, sizeof(struct sockaddr));
    
    /* Fill in the remainder of the request. */
    req.arp_flags = ATF_PERM;
    memset(req.arp_dev, 0, sizeof(req.arp_dev));
    
    if (ioctl(fd, SIOCDARP, &req) < 0) {
        fprintf(stderr,"[%s-%d]""SIOCDARP. error_string:%s.\n", 
            __FUNCTION__, __LINE__, strerror(errno));
    }

    (void) close(fd);
	return (0);
}