#include <sys/ucontext.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void do_inc(long long*);
void do_printf(const char* str)
{
    printf("Message: %s\n", str);
}

int main()
{
    long long a = 0;
    for(;;)
    {
        do_inc(&a);
        printf("%lld\n", a);
        sleep(1);
    }
    return 0;
}