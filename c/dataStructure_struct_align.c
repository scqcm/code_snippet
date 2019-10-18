
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

/*
#pragma pack(2)
...
#pragma pack()

struct __attribute__((aligned (64)))
{
    uint8_t c1;
} s2;

sizeof(struct s2) = 64;
*/
typedef struct m
{
    char _a;
    int _b;
    short _c;
} __attribute__((packed)) T_FOO;


int main()
{
    T_FOO a;
    int i;
    char *p;
    printf("T_FOO = %d, align = packed.\n", sizeof(T_FOO));

    printf("_a -> %d, _b -> %d, _c -> %d\n",
        (unsigned int)(void*)&a._a - (unsigned int)(void*)&a,
        (unsigned int)(void*)&a._b  - (unsigned int)(void*)&a,
        (unsigned int)(void*)&a._c - (unsigned int)(void*)&a);

    for(i=0; i<10; i++) {
        /*申请到的内存是16BYTE*/
        p = malloc(1);
        printf("%p\n", p);
    }

    char array[18] = {0};
    printf("sizeof(array)=%d\n", sizeof(array));
    printf("strlen(array)=%d\n", strlen(array));
    return 0;
}
/*
成员的align决定成员起始地址，结构体的align决定结构体的大小
T_FOO=12,align=1
_a -> 0, _b -> 4, _c -> 8

T_FOO=16,align=8
_a -> 0, _b -> 4, _c -> 8

T_FOO=32,align=32
_a -> 0, _b -> 4, _c -> 8

add __attribute__((aligned(8))) int _b;
T_FOO=16,align=8
_a -> 0, _b -> 8, _c -> 12

__attribute__((aligned(16))) int _b;
T_FOO=32,align=32
_a -> 0, _b -> 16, _c -> 20
*/
