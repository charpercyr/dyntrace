#ifndef DYNTRACE_UTIL_BARRIER_HPP_
#define DYNTRACE_UTIL_BARRIER_HPP_

#include <pthread.h>

namespace dyntrace
{
    class barrier
    {
    public:
        barrier(const barrier& b) = delete;
        barrier(barrier&&) = delete;
        barrier& operator=(const barrier&) = delete;
        barrier& operator=(barrier&&) = delete;

        explicit barrier(uintptr_t n)
        {
            pthread_barrier_init(&_barrier, nullptr, n);
        }
        ~barrier()
        {
            pthread_barrier_destroy(&_barrier);
        }

        void wait()
        {
            pthread_barrier_wait(&_barrier);
        }

    private:
        pthread_barrier_t _barrier{};
    };
}

#endif