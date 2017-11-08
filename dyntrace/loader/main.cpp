
#include <atomic>
#include <cstdio>
#include <memory>

#include <pthread.h>
#include <unistd.h>

#include <time.h>

class loader
{
public:
    loader()
    {
        pthread_create(&_th, nullptr, loader::_run, this);
    }
    ~loader()
    {
        _running = false;
        pthread_join(_th, nullptr);
    }
private:
    static void* _run(void* _this)
    {
        reinterpret_cast<loader*>(_this)->run();
        return nullptr;
    }

    void run()
    {
        timespec t{.tv_sec = 0, .tv_nsec = 100'000'000};
        while(_running)
        {
            printf("Lib\n");
            for(int i = 0; i < 10 && _running; i++)
                nanosleep(&t, nullptr);
        }
    }

    std::atomic<bool> _running{true};
    pthread_t _th{0};
};

static std::unique_ptr<loader> _loader{nullptr};

void __attribute__((constructor)) init()
{
    printf("Insert\n");
    _loader = std::make_unique<loader>();
}

void __attribute__((destructor)) fini()
{
    printf("Remove\n");
    _loader = nullptr;
}