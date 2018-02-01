#include "file-lock.h"
#include "util.h"

#include <stdio.h>
#include <unistd.h>

#define LOCK_NAME "exlock"

int main(void)
{
        char dirbuf[256];
        struct file_lock lk = FILE_LOCK_INIT;
        cstring fpath = CSTRING_INIT;

        getcwd(dirbuf, 256);

        cstring_addstr(&fpath, dirbuf);
        cstring_addch(&fpath, '/');
        cstring_addstr(&fpath, LOCK_NAME);

        printf("Holding lock: %s ...", fpath.buf);
        if (file_lock_hold(&lk, fpath.buf, 10) < 0) {
                file_lock_release(&lk);
                printf("..Failed!\n");
                return 1;
        }
        printf("...Done!\n");

        printf("Sleeping for 20 seconds...\n");
        sleep_ms(20000);
        printf("...Done!\n");

        printf("Release lock...");
        file_lock_release(&lk);
        printf("...Done!\n");

        return 0;
}
