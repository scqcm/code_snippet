
#include <stdio.h>
#include<string.h>

int
test_strtok(void)
{
    char str[] = "mv  a.cccc  b.cccc   c";
    char *delim = " ";
    char *p; 
    p = strtok(str, delim);
    
    while(p)
    {  
        printf("%s\n", p);  
        p = strtok(NULL, delim);  
    }
    printf("%s\n", str);
    
    return 0;
}

int
test_strtok_r(void)
{
    char str[] = "mv  a.cccc  b.cccc   c";
    char *delim = " ";
    char *saveptr = NULL;
    char *p; 
    p = strtok_r(str, delim, &saveptr);
    
    while(p)
    {  
        printf("%s\n", p);  
        p = strtok_r(NULL, delim, &saveptr); 
    }
    printf("%s\n", str);
    
    return 0;
}

int
main(void)
{
    printf("%s\n", "test_strtok:");
    test_strtok();
    
    printf("%s\n", "test_strtok_r:");
    test_strtok_r();
    
    return 0;
}
