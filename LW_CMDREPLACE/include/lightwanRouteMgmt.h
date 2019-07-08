/*******************************************************************************
 * LEGALESE:   Copyright (c) 2018 LightWAN Corporation.
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
 ******************************************************************************/
 
#ifndef LIGHTWANROUTEMGMT_H
#define LIGHTWANROUTEMGMT_H

#include "appexDefs.h"

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
    );

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
    );
	
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
    );
   
#endif