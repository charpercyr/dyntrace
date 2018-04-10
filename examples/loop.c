#include <sys/ucontext.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>

uint64_t do_inc();

int main()
{
    intptr_t a = 0;
    for(;;)
    {
        printf("%lx\n", do_inc());
        sleep(1);
    }
    return 0;
}