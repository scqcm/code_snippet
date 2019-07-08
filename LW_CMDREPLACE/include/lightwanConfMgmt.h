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
 * FILE NAME :      lightwanConfMgmt.h
 *
 * DESCRIPTION :    lightwan conf file opertion
 *
 * AUTHOR :         sunchao
 *
 * HISTORY :        sunchao     2019/3/30  create
 * Note:
 *       sed-4.2.2
 ******************************************************************************/
 
#ifndef LIGHTWANCONFMGMT_H
#define LIGHTWANCONFMGMT_H

#include "appexDefs.h"

/*******************************************************************************
 * NAME:  LW_SedReplace
 *
 * DESCRIPTION:
 *      Attempt to match regexp against the pattern space.  
 *      If successful, replace that portion matched with replacement.
 *
 * INPUTS:
 *      FileName: an input stream
 *      Regexp: a regular expression
 *      Replacement: contain the special character
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_SedReplace(
    __in char *FileName,
    __in char *Regexp,
    __in char *Replacement
);

/*******************************************************************************
 * NAME:  LW_SedDelete
 *
 * DESCRIPTION:
 *      Delete lines that match regexp.
 *
 * INPUTS:
 *      FileName: an input stream
 *      Regexp: a regular expression
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_SedDelete(
    __in char *FileName,
    __in char *Regexp
);
    
#endif