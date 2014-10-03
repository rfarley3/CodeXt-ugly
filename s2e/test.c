#include <errno.h>
#include <stdio.h>
#include <stdlib.h>

#include "s2e.h"

int main(int argc, char *argv[])
{
        char **vector;
        int args;

        s2e_disable_all_apic_interrupts();
        s2e_enable_forking();

        s2e_make_symbolic(&args, sizeof(args), "Number of arguments");

        if (args < 1 || args > 4)
        {
                s2e_get_example(&args, sizeof(args));
                printf("Bad value for args: %d\n", args);
                s2e_kill_state(0, "bad value for args");
                return 2;
        }

        printf("Good value for args\n"); fflush(stdout);

        args= 5;

        s2e_get_example(&args, sizeof(args));
        printf("Got value for args: %d\n", args);
        fflush(stdout);

        printf("Before malloc vector\n");
        vector= malloc((args+1)*sizeof(*vector));
        printf("After malloc vector\n");

        s2e_kill_state(0, "after malloc");
}
