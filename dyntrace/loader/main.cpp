
#include <thread>

#include <unistd.h>

using namespace std;

void func()
{
    for(;;)
    {
        printf("Lib\n");
        sleep(1);
    }
}

void __attribute__((constructor)) init()
{
    thread th(func);
    th.detach();
}