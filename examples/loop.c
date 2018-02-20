#include <sys/ucontext.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>

void do_inc(long long*);

void handle_sigsegv(int sig, siginfo_t* siginfo, void* _ctx)
{
    ucontext_t* ctx = (ucontext_t*)_ctx;
    printf("SEGV at 0x%llx\n", ctx->uc_mcontext.gregs[16]);
    kill(getpid(), SIGKILL);
}

int main()
{
    struct sigaction act;
    act.sa_flags = SA_SIGINFO;
    act.sa_sigaction = &handle_sigsegv;
    sigaction(SIGSEGV, &act, NULL);
    long long a = 0;
    for(;;)
    {
        do_inc(&a);
        //printf("%lld\n", a);
        sleep(1);
    }
    return 0;
}