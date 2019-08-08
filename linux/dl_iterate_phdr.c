
/*
 *gcc dl_iterate_phdr.c -ldl 
 */

#define _GNU_SOURCE
#include <link.h>
#include <dlfcn.h>
#include <stdlib.h>
#include <stdio.h>

static int
callback(struct dl_phdr_info *info, size_t size, void *data)
{ 
    int j;

    printf("name=%s (%d segments)\n", info->dlpi_name, info->dlpi_phnum);

    for (j = 0; j < info->dlpi_phnum; j++) {
        void* addr = (void *) (info->dlpi_addr + info->dlpi_phdr[j].p_vaddr);
        printf("\t\t header %2d: address=%10p\n", j, addr);
        Dl_info dlinfo;
        dladdr(addr, &dlinfo);
        printf("\t %s : %s\n", dlinfo.dli_fname, dlinfo.dli_sname);
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    dl_iterate_phdr(callback, NULL);
    exit(EXIT_SUCCESS);
}
