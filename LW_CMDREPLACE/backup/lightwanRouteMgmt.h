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

typedef enum {
    LW_IPROUTE_ADD=1,
    LW_IPROUTE_DEL,
    LW_IPROUTE_REPLACE,
    
    LW_IPROUTE_MAX,
} LW_IPROUTE_OPTYPE;

typedef enum {
    LW_IPRULE_ADD=1,
    LW_IPRULE_DEL,
    
    LW_IPRULE_MAX,
} LW_IPRULE_OPTYPE;

/*******************************************************************************
 * NAME:  LW_IPRouteOp
 *
 * DESCRIPTION:
 *      Modify routing table
 *
 * INPUTS:
 *      OpType: Operation type
 *      ArgAtr: argument string
 *      ArgLen: length of argstr, including '\0'
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      ip route replace default nexthop via xxx dev xxx
 *      char argstr[] = "default nexthop via 10.1.4.1 dev eno16777736";
 *      iproute_op( LW_IPROUTE_REPLACE, argstr, sizeof(argstr));
 ******************************************************************************/
int 
LW_IPRouteOp(
    __in LW_IPROUTE_OPTYPE OpType, 
    __in char *ArgStr, 
    __in int ArgLen
    );

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
 *EXAMPLE:
 *      ip rule add table 231 prio 1000
 *      char argstriprule[] = "table 231 prio 1000";
 *      iprule_op( LW_IPRULE_ADD, argstriprule, sizeof(argstriprule));
 ******************************************************************************/
int 
LW_IPRuleOp(
    __in LW_IPRULE_OPTYPE OpType, 
    __in char *ArgStr, 
    __in int ArgLen
    );
    
#endif