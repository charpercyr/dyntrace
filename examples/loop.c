#include <stdio.h>
#include <unistd.h>

int main()
{
    for(;;)
    {
         printf("Loop\n");
         sleep(1);
    }
    return 0;
}