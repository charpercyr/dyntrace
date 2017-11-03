
#include <pthread.h>
#include <stdio.h>

#include <unistd.h>


void* func(void*)
{
    for(;;)
    {
        printf("Lib\n");
        sleep(1);
    }
}

void __attribute__((constructor)) init()
{
    pthread_t th;
    pthread_create(&th, nullptr, func, nullptr);
    pthread_detach(th);
}