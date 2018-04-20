#ifndef DYNTRACE_FASTTP_BUFFER_WRITER_HPP_
#define DYNTRACE_FASTTP_BUFFER_WRITER_HPP_

#include "code_ptr.hpp"

#include <cstddef>
#include <cstdint>
#include <cstring>

namespace dyntrace::fasttp
{
    class buffer_writer
    {
    public:
        explicit buffer_writer(code_ptr ptr) noexcept
            : _ptr{ptr} {}

        template<typename T>
        void write(const T& val) noexcept
        {
            write_bytes(&val, sizeof(val));
        }

        template<typename R, typename...Args>
        void write(R(&func)(Args...)) noexcept
        {
            *_ptr.as<void**>() = reinterpret_cast<void*>(&func);
            advance(sizeof(void*));
        };

        void write_bytes(const void* b, size_t size) noexcept
        {
            memcpy(_ptr.as_ptr(), b, size);
            advance(size);
        }

        void advance(size_t count) noexcept
        {
            _ptr += count;
        }

        code_ptr ptr() const noexcept
        {
            return _ptr;
        }

    private:
        code_ptr _ptr;
    };
}

#endif