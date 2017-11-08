
#include<stdio.h>

#include <sys/user.h>

void on_enter(void* caller, struct user_regs_struct* regs)
{
    printf("Enter %p", caller);
}

void on_exit(void* caller, struct user_regs_struct* regs)
{
    printf("Exit %p", caller);
}