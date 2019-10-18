
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <unistd.h>

void
main(void)
{
    int fd = -1;
    int ret = 0;

    long sizepage = sysconf (_SC_PAGESIZE);
    printf("sizepage = %d\n", sizepage);
getchar();
	char * FilePath = "/home/num.txt";
    int open_flags = O_WRONLY | O_CREAT | O_EXCL;
    fd = open(FilePath, open_flags);
    if(fd < 0)
    {
        printf("open failed, filepath:%s error_string:%s\n", FilePath, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }

CommonReturn:
    if(fd >= 0)
    {
        close(fd);
    }
    return;
}


