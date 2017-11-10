#ifndef DYNTRACE_DYNTRACE_LOADER_CODE_ALLOCATOR_HPP_
#define DYNTRACE_DYNTRACE_LOADER_CODE_ALLOCATOR_HPP_

#include <bitset>
#include <unordered_map>
#include <sys/user.h>

#include <process/process.hpp>
#include <util/util.hpp>

namespace dyntrace::loader
{

    template<size_t object_size>
    class code_allocator
    {
        class page
        {
        public:
            static constexpr uintptr_t alignment = dyntrace::next_pow2(object_size);
            static constexpr uintptr_t size = PAGE_SIZE;
            static constexpr uintptr_t slots = size / alignment;

            page(void* base)
                    : _base{reinterpret_cast<uintptr_t>(base)} {}

            size_t count() const noexcept
            {
                return _allocated.count();
            }

            bool full() const noexcept
            {
                return count() == slots;
            }

            void* base() const noexcept
            {
                return reinterpret_cast<void*>(_base);
            }

            void* alloc() noexcept
            {
                for(size_t i = 0; i < slots; ++i)
                {
                    if(!_allocated[i])
                    {
                        _allocated[i] = true;
                        return reinterpret_cast<void*>(_base + i * alignment);
                    }
                }
                return nullptr;
            }

            void free(void* ptr) noexcept
            {
                size_t idx = (reinterpret_cast<uintptr_t>(ptr) - _base) / alignment;
                if(idx < slots)
                    _allocated[idx] = false;
            }

        private:
            uintptr_t _base;
            std::bitset<slots> _allocated;
        };
    public:
        static constexpr uintptr_t alignment = page::alignment;

        explicit code_allocator(const process::process& proc)
            : _proc{proc} {}

        void* alloc(size_t max_dist)
        {
        }

        void free(void* ptr)
        {

        }

    private:

        page new_page()
        {

        }

        const process::process& _proc;
        std::unordered_map<uintptr_t, page> _partial_pages;
        std::unordered_map<uintptr_t, page> _full_pages;
    };
}

#endif