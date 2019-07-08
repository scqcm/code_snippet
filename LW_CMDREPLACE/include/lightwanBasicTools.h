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
 * FILE NAME :      lightwanBasicTools.h
 *
 * DESCRIPTION :    lightwan basic tools
 *
 * AUTHOR :         sunchao
 *
 * HISTORY :        sunchao     2019/3/30  create
 * Note:
 *       coreutils-8.22, procps-ng-3.3.15
 ******************************************************************************/

#ifndef LIGHTWANBASICTOOLS_H
#define LIGHTWANBASICTOOLS_H

#include <stdbool.h>
#include "appexDefs.h"

/*******************************************************************************
 * NAME:  LW_DoCopy
 *
 * DESCRIPTION:
 *      copy a regular file or a directory
 *
 * INPUTS:
 *      SrcName: source file/directory, '*', '.', '..' are not supported.
 *      DstName: Destination directory, can not be a file.
 *      IsRecursive: if source is a directory, it must be true.
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoCopy (
    __in char    *SrcName, 
    __in char    *DstName,
    __in bool    IsRecursive
    );
    
/*******************************************************************************
 * NAME:  LW_DoRm
 *
 * DESCRIPTION:
 *      remove a file or a directory
 *
 * INPUTS:
 *      SrcName: source file/directory, '*', '.', '..' are not supported.
 *      IsRecursive: if source is a directory, it must be true.
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_DoRm (
    __in char    *SrcName, 
    __in bool    IsRecursive
    );
    
/*******************************************************************************
 * NAME:  LW_IsProcessExist
 *
 * DESCRIPTION:
 *      test if the process with specified name exist. 
 *
 * INPUTS:
 *      Name: the process name.
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_IsProcessExist (
    __in const char * Name
    );

/*******************************************************************************
 * NAME:  LW_KillProcess
 *
 * DESCRIPTION:
 *      terminate a process. 
 *
 * INPUTS:
 *      Pid: the process pid.
 * RETURN:
 *     !0    failed
 *      0   succeed
 *EXAMPLE:
 *      
 ******************************************************************************/
int
LW_KillProcess (
    __in int Pid
    );
    
#endif