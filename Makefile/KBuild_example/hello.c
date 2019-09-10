#include<stdio.h>
#include"autoconf.h"
#include"myprint.h"

void main() {
#ifdef CONFIG_ARM
	printf("ARM PLAT!\n");
#endif

#ifdef CONFIG_x86
	printf("x86 PLAT!\n");
#endif

#ifdef CONFIG_MYPRINT
	myprint();
#endif
}