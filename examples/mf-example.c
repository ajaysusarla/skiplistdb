#include "mappedfile.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <uuid/uuid.h>


static const char *fname = "/tmp/mf.data";


int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        struct mappedfile *mf;
        uuid_t uuid;
        unsigned char stackbuf[64];
        unsigned char *sptr;
        char uuidstr[36];
        size_t nbytes;
        int ret = EXIT_SUCCESS;

        memset(&stackbuf, 0, 64);
        sptr = stackbuf;

        /* Generate a new uuid */
        uuid_generate(uuid);
        uuid_unparse_lower(uuid, uuidstr);

        /* Index */
        *((uint32_t *)sptr) = hton32(0);
        sptr += sizeof(uint32_t);

        /* UUID */
        memcpy(sptr, &uuidstr, 36);
        sptr += 36;

        /* Write to file */
        if (mappedfile_open(fname, MAPPEDFILE_RW_CR, &mf) != 0) {
                fprintf(stderr, "Could not create %s!", fname);
                ret = EXIT_FAILURE;
                goto fail1;
        }

        if (mappedfile_write(&mf, &stackbuf, 64, &nbytes) != 0) {
                fprintf(stderr, "Could not write to file %s!",
                        fname);
                ret = EXIT_FAILURE;
                goto fail2;
        }

        mappedfile_flush(&mf);

        printf("%zu bytes written to %s.\n", nbytes, fname);

        mappedfile_close(&mf);

        printf("Sleeping for 20 seconds. Run `hexdump %s`\n", fname);
        sleep(20);

        /* Update Index in file */
        if (mappedfile_open(fname, MAPPEDFILE_RW_CR, &mf) != 0) {
                fprintf(stderr, "Could not create %s!", fname);
                ret = EXIT_FAILURE;
                goto fail1;
        }

        sptr = mf->ptr;
        *((uint32_t *)sptr) = hton32(29);

        mappedfile_flush(&mf);

fail2:
        mappedfile_close(&mf);

fail1:
        exit(ret);
}
