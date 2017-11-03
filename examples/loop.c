#include <stdio.h>

#include <unistd.h>
#include <stdlib.h>

void* test_malloc(size_t size)
{
    printf("malloc %lu\n", size);
    void* res = malloc(size);
    printf("returned %p\n", res);
    return res;
}

void* test_free(void* ptr)
{
    printf("free %p\n", ptr);
    free(ptr);
    printf("returned\n");
}

void* __libc_dlopen_mode(const char*, int);

void* test_dlopen(const char* path, int mode)
{
    printf("dlopen %s(%p) %d\n", path, path, mode);
    void* res = __libc_dlopen_mode(path, mode);
    printf("returned %p\n", res);
    return res;
}

int main()
{
    for(;;)
    {
         printf("Loop\n");
         sleep(1);
    }
    return 0;
}