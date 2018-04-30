#include <sys/ucontext.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <stdint.h>

void do_inc(unsigned long*);

int main()
{
    unsigned long a = 0;
    for(;;)
    {
        do_inc(&a);
        printf("%ld\n", a);
        sleep(1);
    }
    return 0;
}