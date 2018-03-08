
#include <dlfcn.h>

void* dyntrace_dlopen(const char* file, int flags)
{
    return dlopen(file, flags);
}

int dyntrace_dlclose(void* handle)
{
    return dlclose(handle);
}