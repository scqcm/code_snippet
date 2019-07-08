#include <stdio.h> 
#include <time.h> 
/************************************************************************
 ** 函数名: get_sys_runtime
 ** 函数描述: 返回系统运行时间
 ** 参数: [in] 1 - 秒,2 - 毫秒
 ** 返回: 秒/毫秒
 ************************************************************************/ 
static long 
get_sys_runtime(int type) 
{
    struct timespec times = {0, 0}; 
    long time; 
    clock_gettime(CLOCK_MONOTONIC, &times);
    printf("CLOCK_MONOTONIC: %lu, %lu\n", times.tv_sec, times.tv_nsec); 
    if (1 == type)
    {
        time = times.tv_sec; 
    }
    else
    { 
        time = times.tv_sec * 1000 + times.tv_nsec / 1000000; 
    }
    
    printf("time = %ld\n", time); 
    return time; 
}

void
calculate_run_time(void)
{
    clock_t start, end;
    int ret, i;
    char * cmd;
    
    start = clock();           /*记录起始时间*/
    for(i=0; i<10000; i++) {
        cmd = "add 1811210002_44 lan_dynroute_ipset_eth2\n";
        ret = printf("%s\n", cmd);
    } 
    end = clock();           /*记录结束时间*/
    {
        double seconds  =(double)(end - start)/CLOCKS_PER_SEC;
        fprintf(stderr, "Use time is(after diff_10): %.8f\n", seconds);
        fprintf(stderr, "Use time is(after diff_10): %.d\n", end - start);
    } 
}    

int 
main(int argc,char *argv[]) 
{ 
    long sec, millisecond; 
    sec = get_sys_runtime(1); 
    millisecond = get_sys_runtime(2); 
    printf("sec = %ld, millisecond = %ld\n", sec, millisecond);
    
    printf("\ncalculate_run_time:\n");
    calculate_run_time();
    return 0; 
}
