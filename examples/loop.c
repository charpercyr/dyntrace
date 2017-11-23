#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

void do_inc(long long*);

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