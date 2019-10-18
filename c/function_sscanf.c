#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>

typedef struct PHYSLOT_INFO {
    char serialNum[16];
    uint8_t portNum;
} PHYSLOT_INFO_S;

static uint8_t s_phySlotNum;
static PHYSLOT_INFO_S s_phySlotInfo[8];

void
main(void)
{
    int ret;
    char cardSerial[8] = "123456";
    ret = sscanf("Serial Number 		=  R04", "%*[^=]=%*[ ]%5c", cardSerial);

    printf("%s\n", cardSerial);
    printf("%d\n", sizeof(PHYSLOT_INFO_S));
    printf("%d\n", sizeof(s_phySlotInfo));
}