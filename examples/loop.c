#include <stdio.h>
#include <time.h>
#include <math.h>

int do_loop_on(int a, int b)
{
    return a + b;
}

int do_loop_off(int a, int b)
{
    return a + b;
}

#define ITER 1000
#define STEPS 100000

double run(int(*func)(int, int))
{
    double avg = 0;
    for (int i = 0; i < ITER; ++i)
    {
        int a = 0;
        clock_t begin = clock();
        for (int j = 0; j < STEPS; ++j)
        {
            func(a++, 10);
        }
        clock_t end = clock();
        double elapsed = (double) (end - begin) / CLOCKS_PER_SEC;
        avg += elapsed;
    }
    avg /= ITER;
    return avg;
}

int main()
{
    double time_on = run(do_loop_on);
    double time_off = run(do_loop_off);
    double diff = fabs(time_off - time_on);
    printf("Loop on  : %fs\n", time_on);
    printf("Loop off  : %fs\n", time_off);
    printf("Diff: %fus, %fns per call\n", diff * 1e6, (diff / STEPS) * 1e9);
    return 0;
}