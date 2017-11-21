#include <stdio.h>

#include <unistd.h>

void do_loop(const char* str)
{
    printf("Loop %s\n", str);
}

int main()
{
    int a = 0;
    for(;;)
    {
        do_loop("Hello");
        sleep(1);
    }
    return 0;
}