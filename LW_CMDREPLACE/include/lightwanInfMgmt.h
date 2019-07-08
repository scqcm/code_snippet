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
 * FILE NAME :      lightwanInfMgmt.h
 *
 * DESCRIPTION :    lightwan interface opertion
 *
 * AUTHOR :         sunchao
 *
 * HISTORY :        sunchao     2019/3/30  create
 * Note:
 *       ethtool-4.0, net-tools-2.0
 ******************************************************************************/
 
#ifndef LIGHTWANINFMGMT_H
#define LIGHTWANINFMGMT_H

#include "appexDefs.h"

#define LW_INFSPEED_10		10
#define LW_INFSPEED_100		100
#define LW_INFSPEED_1000		1000
#define LW_INFSPEED_2500		2500
#define LW_INFSPEED_10000		10000
#define LW_INFSPEED_UNKNOWN		-1

#define LW_INFDUPLEX_HALF		0x00
#define LW_INFDUPLEX_FULL		0x01
#define LW_INFDUPLEX_UNKNOWN		-1

#define LW_INFAUTONEG_DISABLE		0x00
#define LW_INFAUTONEG_ENABLE		0x01
#define LW_INFAUTONEG_UNKNOWN		-1

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
    __in const char *IfName,
    __in int SpeedWanted,
    __in unsigned char DuplexWanted,
    __in unsigned char AutonegWanted
);

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
    __in const char *IfName, 
    __in int mtu
    );

/*******************************************************************************
 * NAME:  LW_DoSetEtherMac
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
    __in const char *IfName, 
    __in char *Mac
    );

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
    __in const char *IfName
    );
    
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
    __in const char *IfName
    );
    
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
    __in char *IPAddr,
    __in char *EtherAddr
    );

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
    __in char *IPAddr
    );
    
#endif