#include <stdio.h>
#include <unistd.h>

void do_loop(void)
{
    printf("Loop\n");
}

int main()
{
    for(;;)
    {
        do_loop();
         sleep(1);
    }
    return 0;
}