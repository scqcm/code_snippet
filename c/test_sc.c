
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>

#define LW_RTC_WRITEFILE_IS_PROC    0
#define LW_RTC_PROC_IPSET           "/proc/ipset"

struct a_struct;
struct a_struct
{
	int c;
	int (*g)();
	enum Season{spring,summer,autumn=5,winter};
}a_real;
int a_global;
static int
_LW_RTCWriteFile(
    const char*Cmd,
    int CmdLen,
    const char *FilePath,
    int IsSyncFlagNeeded
)
{
    int fd = -1;
    int ret = 0;
    int len = 0;
//	int autumn =0;
    printf("%d\n", autumn);
getchar();
    fd = open(FilePath, O_WRONLY | IsSyncFlagNeeded ? (O_SYNC | O_CREAT | O_TRUNC | O_RDWR): 0);
    if(fd < 0)
    {
        printf("open failed, filepath:%s cmd:%s error_string:%s\n", FilePath, Cmd, strerror(errno));
        ret = -1;
        goto CommonReturn;
    }

    //printf("Exec Path:%s, Cmd:%s\n", FilePath, Cmd);

    len = write(fd, Cmd, CmdLen);
    if(len != CmdLen)
    {
        printf("write failed, filepath:%s, cmd:%s error_string:%s return:%d\n", 
            FilePath, Cmd, strerror(errno), len);
        ret = -1;
    }

    
CommonReturn:
    if(fd >= 0)
    {
        close(fd);
    }
    return ret;   
}
void
main(void)
{
    /*   
    unsigned int ip = 0x01020304;
    unsigned int beIp = htonl(ip);
    char strip[50] ={0};
    //sprintf(strip, "%pI4\n", &beIp);
    printf("asdf\n""1234\n""%s\n", strip);
    
    struct st{
        int i;
        char c;
    };
    
    struct st st_a = {.i=10, .c='a'};
    
    printf("sizeof(p struct)= %d\n", sizeof(struct st *));
    printf("sizeof(array)= %d\n", sizeof(strip));
    */
    
    clock_t start, end;
    int ret, i;
    char * cmd;
    
    start = clock();           /*记录起始时间*/
    for(i=0; i<5; i++) {
        cmd = "create 1811210002_44 ipset super\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
        cmd = "del 1811210002_44 lan_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
        cmd = "add 1811210002_44 lan_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
        cmd = "del 1811210002_44 lan_dynroute_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
        cmd = "add 1811210002_44 lan_dynroute_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }
    
    start = clock();           /*记录起始时间*/
    for(i=0; i<1; i++) {
        cmd = "create 1811210002_44 ipset super\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }
    
        start = clock();           /*记录起始时间*/
    for(i=0; i<1; i++) {
        cmd = "del 1811210002_44 lan_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }
            start = clock();           /*记录起始时间*/
    for(i=0; i<1; i++) {
        cmd = "add 1811210002_44 lan_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }
    
        start = clock();           /*记录起始时间*/
    for(i=0; i<1; i++) {
        cmd = "del 1811210002_44 lan_dynroute_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }  
            start = clock();           /*记录起始时间*/
    for(i=0; i<1; i++) {
        cmd = "add 1811210002_44 lan_dynroute_ipset_eth2\n";
        ret = _LW_RTCWriteFile(cmd, strlen(cmd), LW_RTC_PROC_IPSET, 0);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    }  
    
	return;
}

