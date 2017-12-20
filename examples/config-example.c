/* Example config file available in tests/data/sdb-example.conf */
#include "config.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>


int main(int argc, char **argv)
{
        if (argc !=2) {
                fprintf(stderr, "%s <filename>\n", argv[0]);
                return 1;
        }

        load_config(argv[1], NULL, 0);

        return 0;
}
