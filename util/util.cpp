#include "util.hpp"

#include "../process/error.hpp"

void dyntrace::hexdump(void *addr, size_t size) noexcept
{
    auto data = reinterpret_cast<uint8_t*>(addr);
    for(size_t i = 0; i < size;)
    {
        printf("%p: ", data + i);
        for(size_t j = 0; j < 16 && i < size; ++i, ++j)
        {
            printf("%.2x ", static_cast<uint32_t>(data[i]) & 0xff);
        }
        printf("\n");
    }
}