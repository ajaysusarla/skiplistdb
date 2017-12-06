#include "mappedfile.h"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *fname = "/tmp/list.dat";
static const int MAX_ELEMENTS = 10;

struct ldata {
        size_t len;
        char *data;
} arr[10] = {
        { 3, "abc" },
        { 3, "def" },
        { 3, "ghi" },
        { 3, "jkl" },
        { 3, "mno" },
        { 3, "pqr" },
        { 3, "stu" },
        { 3, "vwx" },
        { 3, "yz1" },
        { 3, "foo" },
};

struct pointers {
        int count;
        size_t *offsets;
};


int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
        struct mappedfile *mfp;
        struct pointers *ptrs;
        int i, count;;

        ptrs = xmalloc(sizeof(struct pointers));
        memset(ptrs, 0, sizeof(struct pointers));

        mappedfile_open(fname, MAPPEDFILE_WR_CR, &mfp);

        for (i = 0; i < MAX_ELEMENTS; i++) {
                unsigned char stackbuf[20];
                size_t written = 0, siz = 0;
                unsigned char *p;

                memset(&stackbuf, 0, 10);
                p = stackbuf;

                memcpy(p, &arr[i].len, sizeof(arr[i].len));
                p += sizeof(size_t);
                siz += sizeof(size_t);

                memcpy(p, &arr[i].data, sizeof(arr[i].data));
                p += sizeof(arr[i].data);
                siz += sizeof(arr[i].data);

                mappedfile_write(&mfp, (void *)&stackbuf, siz, &written);
                printf("siz:%zu, offset:%zu, written:%zu\n", siz, mfp->offset, written);

                if (root) {
                        cur->next = node;
                        cur = node;
                } else {
                        root = node;
                        cur = node;
                }
        }

        cur = root;
        while(cur) {
                printf("offset: %zu\n", cur->offset);
                cur = cur->next;
        }

        mappedfile_close(&mfp);

        exit(EXIT_SUCCESS);
}
