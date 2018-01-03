#include "strarray.h"
#include "util.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

const char *zsprefix = "zeroskip-";

int main(int argc __attribute__((unused)), char **argv)
{
        struct str_array arr = STR_ARRAY_INIT;
        char **data, **tmp;

        /* Initialise */
        str_array_init(&arr);

        if (get_filenames_with_matching_prefix_abs(argv + 1, zsprefix, &arr) != 0) {
                perror("get_filenames:");
                goto done;
        }

        /* Get the strings */
        data = (char **)str_array_detach(&arr);
        tmp = data;

        /* Print the strings */
        for (; *tmp; tmp++) {
                printf("-> %s\n", *tmp);
        }

        /* Free them */
        for (; *tmp; tmp++)
                free(*tmp);

        free(data);

done:
        /* Free str_array */
        str_array_clear(&arr);

        exit(EXIT_SUCCESS);
}
