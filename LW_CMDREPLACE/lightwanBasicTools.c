
#include <linux/limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <dirent.h>
#include <signal.h>

#include "include/lightwanBasicTools.h"


#define ISSLASH(C) ((C) == '/')
#define CHMOD_MODE_BITS \
  (S_ISUID | S_ISGID | S_ISVTX | S_IRWXU | S_IRWXG | S_IRWXO)
#define SAME_INODE(a, b)    \
    ((a).st_ino == (b).st_ino \
    && (a).st_dev == (b).st_dev)

# define S_IRWXUGO (S_IRWXU | S_IRWXG | S_IRWXO)
#define UINT32_MAX  4294967295U
#define NAME_SIZE_DEFAULT 512

struct dir_list
{
  struct dir_list *parent;
  ino_t ino;
  dev_t dev;
};

static int
copy_internal (
    char    *SrcName,
    char    *DstName,
    struct dir_list *ancestors
    );
/* Return the user's umask, caching the result.

   FIXME: If the destination's parent directory has has a default ACL,
   some operating systems (e.g., GNU/Linux's "POSIX" ACLs) use that
   ACL's mask rather than the process umask.  Currently, the callers
   of cached_umask incorrectly assume that this situation cannot occur.  */
static mode_t
cached_umask (void)
{
  static mode_t mask = (mode_t) -1;
  if (mask == (mode_t) -1)
    {
      mask = umask (0);
      umask (mask);
    }
  return mask;
}

static bool
is_ancestor (const struct stat *sb, const struct dir_list *ancestors)
{
  while (ancestors != 0)
    {
      if (ancestors->ino == sb->st_ino && ancestors->dev == sb->st_dev)
        return true;
      ancestors = ancestors->parent;
    }
  return false;
}

/* Return PTR, aligned upward to the next multiple of ALIGNMENT.
   ALIGNMENT must be nonzero.  The caller must arrange for ((char *)
   PTR) through ((char *) PTR + ALIGNMENT - 1) to be addressable
   locations.  */

static inline void *
ptr_align (void const *ptr, size_t alignment)
{
  char const *p0 = ptr;
  char const *p1 = p0 + alignment - 1;
  return (void *) (p1 - (size_t) p1 % alignment);
}

static char *
last_component (char const *name)
{
    char const *base = name;
    char const *p;
    bool saw_slash = false;

    while (ISSLASH (*base))
        base++;

    for (p = base; *p; p++)
    {
        if (ISSLASH (*p))
            saw_slash = true;
        else if (saw_slash)
        {
            base = p;
            saw_slash = false;
        }
    }

    return (char *) base;
}

static bool
strip_trailing_slashes (char *file)
{
    char *base = last_component (file);
    char *base_lim;
    bool had_slash;
    int len;

    if (! *base)
        base = file;

    len = strlen(base);
    base_lim = base + len - 1;
    had_slash = (*base_lim == '/');
    while (len)
    {
        if (*base_lim == '/')
        {
            *base_lim = '\0';
            len--;
            base_lim--;
        }
        else
        {
            break;
        }
    }

    return had_slash;
}

static bool
sparse_copy (
    int src_fd,
    int dest_fd,
    char *buf,
    size_t buf_size,
    char const *src_name,
    char const *dst_name,
    unsigned long max_n_read
    )
{
    unsigned long total_n_read = 0;

    while (max_n_read)
    {
        int n_read = read(src_fd, buf, buf_size);
        if (n_read < 0)
        {
            if (errno == EINTR)
                continue;
            fprintf(stderr,"[%s-%d]""failed to read %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, src_name, strerror(errno));
            return false;
        }
        if (n_read == 0)
            break;
        max_n_read -= n_read;
        total_n_read += n_read;

        size_t n = n_read;
        char *ptr = buf;
        while (n > 0)
        {
            size_t n_rw = write(dest_fd, ptr, n);
            if (n_rw < 0)
            {
                if (errno == EINTR)
                {
                    continue;
                }
                else
                {
                    fprintf(stderr,"[%s-%d]""failed to write %s. error_string:%s.\n",
                        __FUNCTION__, __LINE__, src_name, strerror(errno));
                    return false;
                }
            }
            ptr += n_rw;
            n -= n_rw;
        }
    }

  return true;
}

static bool
copy_reg (
    char const *SrcName,
    char const *DstName,
    mode_t dst_mode,
    mode_t omitted_permissions,
    struct stat const *src_sb
    )
{
    char *buf;
    char *buf_alloc = NULL;
    int dest_desc;
    int dest_errno;
    int source_desc;
    struct stat sb;
    struct stat src_open_sb;
    bool return_val = true;

    source_desc = open(SrcName, O_RDONLY);
    if (source_desc < 0)
    {
        fprintf(stderr,"[%s-%d]""cannot open %s for reading. error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return false;
    }

    if (fstat (source_desc, &src_open_sb) != 0)
    {
        fprintf(stderr,"[%s-%d]""cannot fstat %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return_val = false;
        goto close_src_desc;
    }

    /* Compare the source dev/ino from the open file to the incoming,
    saved ones obtained via a previous call to stat.  */
    if (! SAME_INODE (*src_sb, src_open_sb))
    {
        fprintf(stderr,"[%s-%d]""skipping file %s, as it was replaced while being copied", __FUNCTION__, __LINE__, SrcName);
        return_val = false;
        goto close_src_desc;
    }

    int open_flags = O_WRONLY | O_CREAT;
    /*
        O_EXCL Ensure that this call creates the file:
        if this flag is specified in conjunction with O_CREAT,
        and pathname already exists, then open() will fail.
    */
    dest_desc = open (DstName, open_flags | O_EXCL, dst_mode & ~omitted_permissions);
    dest_errno = errno;

    if (dest_desc < 0 && dest_errno == EEXIST)
    {
        fprintf(stderr,"[%s-%d]""Dst file %s exists. error_string:%s.\n",
            __FUNCTION__, __LINE__, DstName, strerror(errno));
        return_val = false;
        goto close_src_desc;
    }
    /*
    if (dest_desc < 0 && dest_errno == EISDIR && *DstName && DstName[strlen (DstName) - 1] == '/')
        dest_errno = ENOTDIR;
    */

    if (dest_desc < 0)
    {
        fprintf(stderr,"[%s-%d]""cannot create regular file %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, DstName, strerror(errno));
        return_val = false;
        goto close_src_desc;
    }

    if (fstat (dest_desc, &sb) != 0)
    {
        fprintf(stderr,"[%s-%d]""cannot fstat %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, DstName, strerror(errno));
        return_val = false;
        goto close_src_and_dst_desc;
    }

    typedef unsigned long word;

    /* Choose a suitable buffer size; it may be adjusted later.  */
    size_t buf_alignment = sysconf(_SC_PAGESIZE);;
    size_t buf_alignment_slop = sizeof (word) + buf_alignment - 1;
    size_t buf_size = 64*1024; /*64KB*/

    /* Make a buffer with space for a sentinel at the end.  */
    buf_alloc = malloc (buf_size + buf_alignment_slop);
    if (NULL == buf_alloc)
    {
        fprintf(stderr,"[%s-%d]""malloc fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return_val = false;
        goto close_src_and_dst_desc;
    }
    buf = ptr_align (buf_alloc, buf_alignment);

    if ( ! sparse_copy (source_desc, dest_desc, buf, buf_size,
        SrcName, DstName, UINT32_MAX))
    {
        fprintf(stderr,"[%s-%d]""failed to extend %s.\n", __FUNCTION__, __LINE__, DstName);
        return_val = false;
        goto close_src_and_dst_desc;
    }

    if (omitted_permissions)
    {
        omitted_permissions &= ~ cached_umask ();
        if (omitted_permissions && lchmod(DstName, dst_mode) != 0)
        {
            fprintf(stderr,"[%s-%d]""preserving permissions for %s.\n", __FUNCTION__, __LINE__, DstName);
        }
    }

    close_src_and_dst_desc:
    if (close (dest_desc) < 0)
    {
        fprintf(stderr,"[%s-%d]""failed to close %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, DstName, strerror(errno));
        return_val = false;
    }
    close_src_desc:
    if (close (source_desc) < 0)
    {
        fprintf(stderr,"[%s-%d]""failed to close %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return_val = false;
    }

    free (buf_alloc);
    return return_val;
}


/* Return a freshly allocated string containing the file names
   in directory DIRP, separated by '\0' characters;
   the end is marked by two '\0' characters in a row.
   Return NULL (setting errno) if DIRP cannot be read.
   If DIRP is NULL, return NULL without affecting errno.  */

static char *
streamsavedir (DIR *dirp)
{
    char *name_space = NULL;
    char *name_space_temp = NULL;
    size_t allocated = NAME_SIZE_DEFAULT;
    size_t used = 0;

    if (dirp == NULL)
        return NULL;

    name_space = (char *)malloc(allocated);
    if(NULL == name_space)
    {
        fprintf(stderr,"[%s-%d]""mallic fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }

    for (;;)
    {
        struct dirent const *dp;
        char const *entry;

        errno = 0;
        dp = readdir (dirp);
        if (! dp)
            break;

        /* Skip "", ".", and "..".  "" is returned by at least one buggy
        implementation: Solaris 2.4 readdir on NFS file systems.  */
        entry = dp->d_name;
        if (entry[entry[0] != '.' ? 0 : entry[1] != '.' ? 1 : 2] != '\0')
        {
            size_t entry_size = _D_EXACT_NAMLEN (dp) + 1;
            if (used + entry_size < used)
            {
                fprintf(stderr,"[%s-%d]""error unexpect.\n", __FUNCTION__, __LINE__);
                if (NULL != name_space)
                    free(name_space);
                return NULL;
            }
            if (allocated <= used + entry_size)
            {
                do
                {
                    if (2 * allocated < allocated)
                    {
                        fprintf(stderr,"[%s-%d]""error unexpect.\n", __FUNCTION__, __LINE__);
                        if (NULL != name_space)
                            free(name_space);
                        return NULL;
                    }
                    allocated *= 2;
                }
                while (allocated <= used + entry_size);

                name_space_temp = realloc (name_space, allocated);
                if(NULL == name_space_temp)
                {
                    fprintf(stderr,"[%s-%d]""reallic fail. error_string:%s.\n",
                        __FUNCTION__, __LINE__, strerror(errno));
                    if (NULL != name_space)
                        free(name_space);
                    return NULL;
                }
                else
                {
                    name_space = name_space_temp;
                }
            }
            memcpy (name_space + used, entry, entry_size);
            used += entry_size;
        }
    }

    name_space[used] = '\0';
    return name_space;
}

/* Return a freshly allocated string containing the file names
   in directory DIR, separated by '\0' characters;
   the end is marked by two '\0' characters in a row.
   Return NULL (setting errno) if DIR cannot be opened, read, or closed.  */
static char *
savedir (
    char const *dir
    )
{
    DIR *dirp = NULL;
    char *name_space = NULL;

    dirp = opendir (dir);
    if(NULL == dirp)
    {
        fprintf(stderr,"[%s-%d]""opendir fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return NULL;
    }

    name_space = streamsavedir (dirp);
    if (dirp && (closedir (dirp) != 0))
    {
        free(name_space);
        return NULL;
    }
    return name_space;
}

/* Read the contents of the directory SRC_NAME_IN, and recursively
   copy the contents to DST_NAME_IN.  NEW_DST is true if
   DST_NAME_IN is a directory that was created previously in the
   recursion.   SRC_SB and ANCESTORS describe SRC_NAME_IN.
   Set *COPY_INTO_SELF if SRC_NAME_IN is a parent of
   (or the same as) DST_NAME_IN; otherwise, clear it.
   Propagate *FIRST_DIR_CREATED_PER_COMMAND_LINE_ARG from
   caller to each invocation of copy_internal.  Be careful to
   pass the address of a temporary, and to update
   *FIRST_DIR_CREATED_PER_COMMAND_LINE_ARG only upon completion.
   Return true if successful.  */

static bool
copy_dir (
    char *src_name_in,
    char *dst_name_in,
    struct dir_list *ancestors
    )
{
    char *name_space;
    char *namep;
    bool ok = true;
    int size_src, size_dst;
    char *src_name = NULL;
    char *dst_name = NULL;

    name_space = savedir (src_name_in);
    if (name_space == NULL)
    {
        /* This diagnostic is a bit vague because savedir can fail in
        several different ways.  */
        fprintf(stderr,"[%s-%d]""cannot access %s.\n",
            __FUNCTION__, __LINE__, src_name_in);
        return false;
    }

    size_src = strlen(src_name_in) + 1 + NAME_MAX + 1;
    strip_trailing_slashes (src_name_in);
    src_name = (char *)malloc(size_src);
    if (NULL == src_name)
    {
        fprintf(stderr,"[%s-%d]""malloc fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return false;
    }
    memset(src_name, 0, size_src);
    memcpy(src_name, src_name_in, strlen(src_name_in));
    *(src_name + strlen(src_name_in)) = '/';
    size_src = strlen(src_name_in) + 1;

    size_dst = strlen(dst_name_in) + 1 + NAME_MAX + 1;
    strip_trailing_slashes (dst_name_in);
    dst_name = (char *)malloc(size_dst);
    if (NULL == dst_name)
    {
        fprintf(stderr,"[%s-%d]""malloc fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return false;
    }
    memset(dst_name, 0, size_dst);
    memcpy(dst_name, dst_name_in, strlen(dst_name_in));
    *(dst_name + strlen(dst_name_in)) = '/';
    size_dst = strlen(dst_name_in) + 1;

    namep = name_space;
    while (*namep != '\0')
    {
        memcpy(src_name + size_src, namep, strlen(namep));
        *(src_name + size_src + strlen(namep)) = '\0';

        memcpy(dst_name + size_dst, namep, strlen(namep));
        *(dst_name + size_dst + strlen(namep)) = '\0';


        ok &= copy_internal (src_name, dst_name, ancestors);

        namep += strlen (namep) + 1;
    }
    free (name_space);

    return ok;
}


static int
copy_internal (
    char    *SrcName,
    char    *DstName,
    struct dir_list *ancestors
    )
{
    struct stat src_sb;
    struct stat dst_sb;
    mode_t src_mode;
    mode_t dst_mode;
    mode_t dst_mode_bits;
    mode_t omitted_permissions;
    int ret;

    if (stat (SrcName, &src_sb) != 0)
    {
        fprintf(stderr,"[%s-%d]""failed to access %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return -1;
    }
    src_mode = src_sb.st_mode;


    /* If the ownership might change, or if it is a directory (whose
    special mode bits may change after the directory is created),
    omit some permissions at first, so unauthorized users cannot nip
    in before the file is ready.  */
    dst_mode_bits = (src_mode) & CHMOD_MODE_BITS;
    omitted_permissions = (dst_mode_bits & (S_ISDIR (src_mode) ? S_IWGRP | S_IWOTH : 0));

    if (S_ISDIR (src_mode))
    {
        struct dir_list dir;

        /* If this directory has been copied before during the
        recursion, there is a symbolic link to an ancestor
        directory of the symbolic link.  It is impossible to
        continue to copy this, unless we've got an infinite disk.  */

        if (is_ancestor (&src_sb, ancestors))
        {
            fprintf(stderr,"[%s-%d]""cannot copy cyclic symbolic link %s.\n",
                __FUNCTION__, __LINE__, SrcName);
            goto un_backup;
        }

        /* Insert the current directory in the list of parents.  */
        dir.parent = ancestors;
        dir.ino = src_sb.st_ino;
        dir.dev = src_sb.st_dev;

        /* POSIX says mkdir's behavior is implementation-defined when
        (src_mode & ~S_IRWXUGO) != 0.  However, common practice is
        to ask mkdir to copy all the CHMOD_MODE_BITS, letting mkdir
        decide what to do with S_ISUID | S_ISGID | S_ISVTX.  */
        if (mkdir (DstName, dst_mode_bits & ~omitted_permissions) != 0)
        {
            fprintf(stderr,"[%s-%d]""cannot create directory %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, DstName, strerror(errno));
            goto un_backup;
        }

        /* We need search and write permissions to the new directory
        for writing the directory's contents. Check if these
        permissions are there.  */

        if (lstat (DstName, &dst_sb) != 0)
        {
            fprintf(stderr,"[%s-%d]""cannot stat %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, DstName, strerror(errno));
            goto un_backup;
        }
        else if ((dst_sb.st_mode & S_IRWXU) != S_IRWXU)
        {
            /* Make the new directory searchable and writable.  */

            dst_mode = dst_sb.st_mode;

            if (lchmod (DstName, dst_mode | S_IRWXU) != 0)
            {
                fprintf(stderr,"[%s-%d]""cannot stat %s. error_string:%s.\n",
                    __FUNCTION__, __LINE__, DstName, strerror(errno));
                goto un_backup;
            }
        }

        /* Copy the contents of the directory.  Don't just return if
        this fails -- otherwise, the failure to read a single file
        in a source directory would cause the containing destination
        directory not to have owner/perms set properly.  */
        ret = copy_dir (SrcName, DstName, &dir);
    }
    else if (S_ISREG (src_mode))
    {
        /* POSIX says the permission bits of the source file must be
        used as the 3rd argument in the open call.  Historical
        practice passed all the source mode bits to 'open', but the extra
        bits were ignored, so it should be the same either way.

        This call uses DST_MODE_BITS, not SRC_MODE.  These are
        normally the same, and the exception (where x->set_mode) is
        used only by 'install', which POSIX does not specify and
        where DST_MODE_BITS is what's wanted.  */
        ret = copy_reg (SrcName, DstName, dst_mode_bits & S_IRWXUGO,
            omitted_permissions, &src_sb);
    }
    else
    {
        fprintf(stderr,"[%s-%d]""%s has unsupport file type", __FUNCTION__, __LINE__, SrcName);
        ret = -1;
    }

un_backup:
    return ret;
}

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
    )
{
    struct stat srcStat;
    struct stat dstStat;
    int ret, size;
    char *temp;
    char *srcName;
    char *dstName;

    srcName = (char *)malloc(strlen(SrcName) + 1);
    if(NULL == srcName)
    {
        fprintf(stderr,"[%s-%d]""failed to alloc memory(%s). error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return -1;
    }

    memset(srcName, 0, (strlen(SrcName) + 1));
    memcpy(srcName, SrcName, strlen(SrcName));

    dstName = (char *)malloc(strlen(DstName) + 1);
    if(NULL == dstName)
    {
        fprintf(stderr,"[%s-%d]""failed to alloc memory(%s). error_string:%s.\n",
            __FUNCTION__, __LINE__, dstName, strerror(errno));
        return -1;
    }

    memset(dstName, 0, (strlen(DstName) + 1));
    memcpy(dstName, DstName, strlen(DstName));

    strip_trailing_slashes (srcName);
    if (stat (srcName, &srcStat) != 0)
    {
        fprintf(stderr,"[%s-%d]""failed to access %s error_string:%s.\n",
            __FUNCTION__, __LINE__, srcName, strerror(errno));
        return -1;
    }

    if (S_ISDIR (srcStat.st_mode) && !IsRecursive)
    {
        fprintf(stderr,"[%s-%d]""omitting directory %s.", __FUNCTION__, __LINE__, SrcName);
        return -1;
    }

    if (stat (dstName, &dstStat)!= 0)
    {
        if (errno != ENOENT)
        {
            fprintf(stderr,"[%s-%d]""failed to access %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, dstName, strerror(errno));
            return -1;
        }
        else
        {
            fprintf(stderr,"[%s-%d]""%s does not exist. error_string:%s.\n",
                __FUNCTION__, __LINE__, dstName, strerror(errno));
            return -1;
        }
    }
    else
    {
        if (!S_ISDIR (dstStat.st_mode))
        {
            fprintf(stderr,"[%s-%d]""%s does not a directory. error_string:%s.\n",
                __FUNCTION__, __LINE__, dstName, strerror(errno));
            return -1;
            /*
            if (S_ISDIR (srcMode))
            {
                fprintf(stderr,"[%s-%d]""cannot overwrite non-directory %s with directory %s",
                    __FUNCTION__, __LINE__, dstName, srcName);
                return -1;
            }
            */
        }
    }

    char arg_base[NAME_MAX] = {0};
    char *target_directory;
    temp = last_component (srcName);
    memcpy(arg_base, temp, strlen(temp));
    strip_trailing_slashes (arg_base);
    if ((strcmp(arg_base, "..") == 0) || (strcmp(arg_base, "*") == 0))
    {
        fprintf(stderr,"[%s-%d]""does not support %s.", __FUNCTION__, __LINE__, arg_base);
        return -1;
    }

    size = strlen(dstName) + 1 + NAME_MAX + 1;
    strip_trailing_slashes (dstName);
    target_directory = (char *)malloc(size);
    if (NULL == target_directory)
    {
        fprintf(stderr,"[%s-%d]""malloc fail. error_string:%s.\n",
            __FUNCTION__, __LINE__, strerror(errno));
        return -1;
    }
    memset(target_directory, 0, size);
    memcpy(target_directory, dstName, strlen(dstName));
    *(target_directory + strlen(dstName)) = '/';
    memcpy(target_directory + strlen(dstName) + 1, arg_base, strlen(arg_base));
    //info,输出重组的命令 SrcName， target_directory
    fprintf(stderr,"[%s-%d]""srcName = %s, target_directory = %s.\n",
        __FUNCTION__, __LINE__, srcName, target_directory);
    ret = copy_internal(srcName, target_directory, NULL);

    free(target_directory);
    return ret;
}


/*
 *rm - remove files or directories
 */

static int
rm_internal(
    char* Name
    )
{
	struct stat st;
	DIR *dir;
	struct dirent *de;
	int ret = 0;

    strip_trailing_slashes (Name);
	/* is it a file or directory? */
	if (lstat(Name, &st) < 0)
    {
        fprintf(stderr,"[%s-%d]""failed to access %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, Name, strerror(errno));
		return -1;
    }

	/* a file, so unlink it */
	if (!S_ISDIR(st.st_mode))
    {
        ret = unlink(Name);
        if (0 != ret)
        {
            fprintf(stderr,"[%s-%d]""failed to unlink %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, Name, strerror(errno));
            return -1;
        }
        else
        {
            return 0;
        }
    }

	/* a directory, so open handle */
	dir = opendir(Name);
	if (dir == NULL)
	{
        fprintf(stderr,"[%s-%d]""failed to open dir %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, Name, strerror(errno));
		return -1;
    }

	/* recurse over components */
	errno = 0;
	while ((de = readdir(dir)) != NULL) {
		char dn[PATH_MAX];
		if (!strcmp(de->d_name, "..") || !strcmp(de->d_name, "."))
			continue;
		sprintf(dn, "%s/%s", Name, de->d_name);
		if (rm_internal(dn) < 0) {
			ret = 1;
			break;
		}
		errno = 0;
	}

	if ((0 == ret) && (0 != errno))
    {
        fprintf(stderr,"[%s-%d]""failed to read dir %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, Name, strerror(errno));
        closedir(dir);
		return -1;
	}
    else if(0 != ret)
    {
        closedir(dir);
        return -1;
    }

	/* close directory handle */
	closedir(dir);
	/* delete target directory */
	ret = rmdir(Name);
    if(0 != ret)
    {
        fprintf(stderr,"[%s-%d]""failed to rm dir %s. error_string:%s.\n",
                __FUNCTION__, __LINE__, Name, strerror(errno));
		return -1;
    }
    else
    {
        return 0;
    }
}

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
    char    *SrcName,
    bool    IsRecursive
    )
{
    struct stat srcStat;
    int ret;
    char *name;

    if (stat (SrcName, &srcStat) != 0)
    {
        fprintf(stderr,"[%s-%d]""failed to access %s error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return -1;
    }

    if (S_ISDIR (srcStat.st_mode) && !IsRecursive)
    {
        fprintf(stderr,"[%s-%d]""omitting directory %s.", __FUNCTION__, __LINE__, SrcName);
        return -1;
    }

    name = (char *)malloc(strlen(SrcName) + 1);
    if(NULL == name)
    {
        fprintf(stderr,"[%s-%d]""failed to alloc memory(%s). error_string:%s.\n",
            __FUNCTION__, __LINE__, SrcName, strerror(errno));
        return -1;
    }

    memset(name, 0, (strlen(SrcName) + 1));
    memcpy(name, SrcName, strlen(SrcName));

    ret = rm_internal(name);

    free(name);
    return ret;
}


/*
 *rm - process operation
 */

static int P_pid;
static char P_cmd[16];

static int
stat2proc(
    int pid
    )
{
    char buf[800]; /* about 40 fields, 64-bit decimal is about 20 chars */
    int num, fd;
    char* tmp;

    snprintf(buf, 32, "/proc/%d/stat", pid);
    if ((fd = open(buf, O_RDONLY, 0)) == -1)
        return 0;
    num = read(fd, buf, sizeof(buf) - 1);
    close(fd);

    if (num < 80)
        return 0;

    buf[num] = '\0';
    tmp = strrchr(buf, ')');      /* split into "PID (cmd" and "<rest>" */
    *tmp = '\0';                  /* replace trailing ')' with NUL */
    /* parse these two strings separately, skipping the leading "(". */
    memset(P_cmd, 0, sizeof P_cmd);          /* clear */
    sscanf(buf, "%d (%15c", &P_pid, P_cmd);  /* comm[16] in kernel */

    if(P_pid != pid)
        return 0;
    else
        return 1;
}

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
    )
{
    struct dirent *ent;          /* dirent handle */
    DIR *dir;
    char name[16] = {0};
    int ret = 0;

    memcpy(name, Name, 15);
    name[15] = '\0';

    dir = opendir("/proc");
    while(( ent = readdir(dir) )){
        if (ent->d_name[0] > '9')
			continue;
		if (ent->d_name[0] < '1')
			continue;
        if(!stat2proc(atoi(ent->d_name)))
            continue;
        ret = strcmp(P_cmd, name);
        if(0 == ret)
        {
            ret = P_pid;
            break;
        }

    }
    closedir(dir);

    return ret;
}

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
    )
{
    if(Pid <= 0)
        return -1;

    return kill(Pid, SIGKILL);
}