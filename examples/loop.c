#include <stdio.h>

#include <unistd.h>

void do_loop(int a)
{
    printf("Loop %d\n", a);
}

int main()
{
    int a = 0;
    for(;;)
    {
        do_loop(a++);
        sleep(1);
    }
    return 0;
}