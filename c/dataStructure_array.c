
#include <stdio.h>
#include <stdlib.h>
typedef char (c_array)[10];
typedef char (* p_array)[10];
int intc[10] = {0};
char ch[10] = "sfsdf";
void
main(void)
{
    char array[10] = {"654321"};
char *p1 = malloc(3);
p1[0] = 'a';
getchar();    
    c_array c = {"zxczxc"};
    p_array p = &array;
    
    printf("%s\n", array);
    return;
}
