int32_t get_ethslot_info(char *tok)
{
#define FILE_PATH_SCMACRO       "/hard_disk/boot/ngmimic.config"
    FILE *fp;
    int i = 0, offset = 0;

    char lineBuf[512] = {0};
    char result[1024] = {0};
    char ethName[32] = {0};
    int portType, slotId;

    fp = fopen(FILE_PATH_SCMACRO, "r");
    if (NULL == fp) {
        fpdebug_fprintf(stderr, "can't open %s, error:%s.\n", FILE_PATH_SCMACRO, strerror(errno));
        return (-1);
    }

    while (NULL != fgets(lineBuf, sizeof(lineBuf), fp)) {
        i = sscanf(lineBuf, "%s %*d %*d %*d %*d %*d %d %d",
            ethName, &portType, &slotId);
        if(i==3)
        {
            offset += sprintf(result + offset,
                    "%s %u SLOT%u|",
                    ethName, portType, slotId);
        }
        memset(lineBuf, 0, sizeof(lineBuf));
        memset(ethName, 0, sizeof(ethName));
    }

    printf("%s", result);
    return 0;
}