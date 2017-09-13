
#include <stdio.h>    /* for printf */
#include <stdlib.h>    /* for exit() definition */
#include <time.h>    /* for clock_gettime */

main(int argc, char **argv)
{
    struct timespec t;
    /* measure monotonic time */
    clock_gettime(CLOCK_REALTIME, &t);
    printf("%f\n", t.tv_sec + t.tv_nsec * 1e-9);
    exit(0);
}

