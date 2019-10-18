
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <regex.h>
#include <fcntl.h>

#include "include/lightwanConfMgmt.h"

#define OP_REPLACE  0x01
#define OP_DELETE   0x02
#define MAX_LINESIZE   1024u

static char buffer_delimiter = '\n';

int
do_sed(
    char *FileName,
    char *Pattern,
    char *Pattern2,
    int OpType
    )
{
    FILE *fpIn = NULL, *fpOut = NULL;
    int fdInput = 0, fdOutput = 0, ret = 0;
    char *fileNameOutput = NULL;
    struct stat inStat;
    int save_umask;
    char *lineBuf = NULL, *lineActive = NULL;
    char *s_accum = NULL, *s_accumActive = NULL;
    size_t sizeLineBuf = 0;
    regex_t rex;
    regmatch_t *pmatch = NULL;
    int regErrorSize = 128;
    char regErrorMsg[regErrorSize];
    char *tmpdir = NULL, *p = NULL;

    ret = regcomp(&rex, Pattern, REG_NEWLINE);
    if(ret != 0){
		regerror(ret, &rex, regErrorMsg, regErrorSize);
        fprintf(stderr,"[%s-%d]""couldn't compile reg %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, Pattern, regErrorMsg);
        return -1;
	}
    pmatch = (regmatch_t*)malloc((rex.re_nsub+1)  *sizeof(regmatch_t));
    if (NULL == pmatch)
    {
        fprintf(stderr,"[%s-%d]""couldn't malloc memory-regmatch_t. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }


    fpIn = fopen (FileName, "r");
    if (NULL == fpIn)
    {
        fprintf(stderr,"[%s-%d]""couldn't open file %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, FileName, strerror(errno));
        return -1;
    }

    /* get the base name */
    tmpdir = (char *)malloc(strlen(FileName) + 1);
    if (NULL == tmpdir)
    {
        fprintf(stderr,"[%s-%d]""couldn't malloc memory-%s. error_string:%s.\n",
            __FUNCTION__, __LINE__, FileName, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }
    strcpy(tmpdir, FileName);

    if ((p = strrchr(tmpdir, '/')))
        *p = '\0';
    else
        strcpy(tmpdir, ".");

    fdInput = fileno (fpIn);
    ret = fstat (fdInput, &inStat);
    if(0!= ret)
    {
        fprintf(stderr,"[%s-%d]""couldn't stat file-%s. error_string:%s.\n",
            __FUNCTION__, __LINE__, FileName, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }

    if (!S_ISREG (inStat.st_mode))
    {
        fprintf(stderr,"[%s-%d]""couldn't edit %s: not a regular file. error_string:%s.\n",
            __FUNCTION__, __LINE__, FileName, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }

    if (NULL == tmpdir)
        tmpdir = "/tmp";

    fileNameOutput = (char *)malloc(strlen(tmpdir) + strlen("sed") + 16);
    if (NULL == fileNameOutput)
    {
        fprintf(stderr,"[%s-%d]""couldn't malloc memory-%s. error_string:%s.\n",
            __FUNCTION__, __LINE__, fileNameOutput, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }
    memset(fileNameOutput, 0, strlen(tmpdir) + strlen("sed") + 16);
    sprintf (fileNameOutput, "%s/%s%d", tmpdir, "sed", (getpid() % 0xffffffff));
    save_umask = umask(0700);
    fdOutput = open(fileNameOutput, O_RDWR | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR);
    umask (save_umask);
    if (-1 == fdOutput)
    {
        fprintf(stderr,"[%s-%d]""Fail to create file-%s. error_string:%s.\n",
            __FUNCTION__, __LINE__, fileNameOutput, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }
    fpOut = fdopen (fdOutput, "w");
    free(tmpdir);

    while (getdelim(&lineBuf, &sizeLineBuf, buffer_delimiter, fpIn) > 0)
    {
        int again = 0;
        int matched = 0;
        int s_accumSize = 0, size = 0;
        s_accumSize = sizeLineBuf + MAX_LINESIZE;
        s_accum = (char *)malloc(s_accumSize);
        if (NULL == s_accum)
        {
            fprintf(stderr,"[%s-%d]""couldn't malloc memory-s_accum. error_string:%s.\n",
                __FUNCTION__, __LINE__, strerror(errno));
            ret = -1;
            goto CommonReturn;
        }
        memset(s_accum, 0, s_accumSize);
        lineActive = lineBuf;
        s_accumActive = s_accum;
        do
        {
            again = 0;
            ret = regexec(&rex, lineActive, rex.re_nsub+1, pmatch, 0);
            if (0 == ret)
            {
                matched = 1;
                if (OP_REPLACE == OpType)
                {
                    int offset = pmatch[0].rm_so;
                    memcpy(s_accumActive, lineActive, offset);
                    lineActive += pmatch[0].rm_eo;
                    s_accumSize -= offset;
                    s_accumActive += offset;
                    if (s_accumSize > strlen(Pattern2))
                    {
                        size = strlen(Pattern2);
                        again = 1;
                    }
                    else
                    {
                        size = s_accumSize - 1;
                    }
                    memcpy(s_accumActive, Pattern2, size);
                    s_accumSize -= size;
                    s_accumActive += size;
                }
                else if (OP_DELETE == OpType)
                {
                    break;
                }
            }
            else if (REG_NOMATCH == ret)
            {
                if(matched && (OP_REPLACE == OpType))
                {
                    if (s_accumSize > strlen(lineActive))
                    {
                        size = strlen(lineActive);
                    }
                    else
                    {
                        size = s_accumSize - 1;
                    }
                    memcpy(s_accumActive, lineActive, size);
                    s_accumSize -= size;
                    s_accumActive += size;
                }
                break;
            }
        }
        while(again);

        if (matched)
        {
            if (OP_REPLACE == OpType)
            {
                fwrite(s_accum, 1, strlen(s_accum), fpOut);
            }
        }
        else
        {
            fwrite(lineBuf, 1, strlen(lineBuf), fpOut);
        }

        free(lineBuf);
        free(s_accum);
        lineBuf = NULL;
        sizeLineBuf = 0;
    }

    fchown (fdOutput, inStat.st_uid, inStat.st_gid);
    fchmod (fdOutput, inStat.st_mode);

CommonReturn:
    if(NULL != fpIn)
        fclose(fpIn);
    if(NULL != fpOut)
        fclose(fpOut);
    if(NULL != fileNameOutput)
    {
        ret = rename(fileNameOutput, FileName);
        if (0 != ret)
        {
            fprintf(stderr,"[%s-%d]""couldn't rename-%s. error_string:%s.\n",
                __FUNCTION__, __LINE__, fileNameOutput, strerror(errno));
        }
        free(fileNameOutput);
    }
    regfree(&rex);



    return ret;
}

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
    )
{
    if((NULL == FileName) || (NULL == Regexp) || (NULL == Replacement))
        return -1;

    return do_sed(FileName, Regexp, Replacement, OP_REPLACE);
}

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

    )
{
    if((NULL == FileName) || (NULL == Regexp))
        return -1;

    return do_sed(FileName, Regexp, NULL, OP_DELETE);
}