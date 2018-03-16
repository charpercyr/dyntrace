/**
 * Utilities for the project.
 */
#ifndef DYNTRACE_UTIL_UTIL_HPP_
#define DYNTRACE_UTIL_UTIL_HPP_

#include <functional>
#include <limits>
#include <string>

namespace dyntrace
{
    template<typename Int, typename Int2>
    constexpr auto ceil_div(Int a, Int2 b) noexcept
    {
        return (a + b - 1) / b;
    }

    template<typename Int, typename Int2>
    constexpr auto max(Int a, Int2 b) noexcept
    {
        return a > b ? a : b;
    }

    template<typename Int, typename Int2>
    constexpr auto min(Int a, Int2 b) noexcept
    {
        return a < b ? a : b;
    }

    /**
     * Returns the next power of two after v
     */
    template<typename Int>
    constexpr Int next_pow2(Int v) noexcept
    {
        --v;
        for(size_t i = 1; i < sizeof(Int)*8; i <<= 1)
        {
            v |= (v >> i);
        }
        return v + 1;
    }

    /**
     * Fast integer log2
     */
    constexpr uint64_t log2(uint64_t v) noexcept
    {
        constexpr uint64_t arr[] = {
            63,  0, 58,  1, 59, 47, 53,  2,
            60, 39, 48, 27, 54, 33, 42,  3,
            61, 51, 37, 40, 49, 18, 28, 20,
            55, 30, 34, 11, 43, 14, 22,  4,
            62, 57, 46, 52, 38, 26, 32, 41,
            50, 36, 17, 19, 29, 10, 13, 21,
            56, 45, 25, 31, 35, 16,  9, 12,
            44, 24, 15,  8, 23,  7,  6,  5
        };
        v |= v >> 1;
        v |= v >> 2;
        v |= v >> 4;
        v |= v >> 8;
        v |= v >> 16;
        v |= v >> 32;
        return arr[((v - (v >> 1))*0x07edd5e59a4e28c2) >> 58];
    }

    /**
     * Converts an integer to a hexadecimal string.
     */
    template<typename Int>
    std::enable_if_t<std::is_integral_v<Int> || std::is_pointer_v<Int>, std::string> to_hex_string(Int i) noexcept
    {
        static constexpr const char chars[] = "0123456789abcdef";
        std::string res;
        auto data = reinterpret_cast<uint8_t*>(&i);
        for(int i = sizeof(Int) - 1; i >= 0; --i)
        {
            res += chars[(data[i] & 0xf0) >> 4];
            res += chars[(data[i] & 0x0f)];
        }
        return res;
    };

    /**
     * Megabyte literal.
     */
    constexpr unsigned long long int operator""_M(unsigned long long int i) noexcept
    {
        return i << 20;
    }

    /**
     * Gigabyte literal.
     */
    constexpr unsigned long long int operator""_G(unsigned long long int i) noexcept
    {
        return i << 30;
    }

#ifdef _DEBUG
    inline void hexdump(const void* addr, size_t size, FILE* stream = stdout) noexcept
    {
        auto data = reinterpret_cast<const uint8_t*>(addr);
        for(size_t i = 0; i < size;)
        {
            fprintf(stream, "%p: ", data + i);
            for(size_t j = 0; j < 16 && i < size; ++i, ++j)
            {
                printf("%.2x ", static_cast<uint32_t>(data[i]) & 0xff);
            }
            printf("\n");
        }
    }

    class assert_failed_error : public std::exception
    {
    public:
        assert_failed_error(const char* file, int line, const char* expr)
            : _msg{std::string{"assert failed at "} + file + "@" + std::to_string(line) + ": " + expr} {}

        const char* what() const noexcept override
        {
            return _msg.c_str();
        }

    private:
        const std::string _msg;
    };

#define dyntrace_assert(x) \
    do \
    { \
        if(!(x)) \
            throw ::dyntrace::assert_failed_error{__FILE__, __LINE__, #x}; \
    } \
    while(0)
#else
#define dyntrace_assert(x)
#endif // _DEBUG
}

#endif