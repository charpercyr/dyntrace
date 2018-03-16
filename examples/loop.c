#include <sys/ucontext.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void do_inc(intptr_t*);

int main()
{
    intptr_t a = 0;
    for(;;)
    {
        do_inc(&a);
        printf("%ld\n", a);
        sleep(1);
    }
    return 0;
}