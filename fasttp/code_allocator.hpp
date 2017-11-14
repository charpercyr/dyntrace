#ifndef DYNTRACE_FASTTP_CODE_ALLOCATOR_HPP_
#define DYNTRACE_FASTTP_CODE_ALLOCATOR_HPP_

#include <bitset>
#include <sys/mman.h>
#include <sys/user.h>

#include <util/util.hpp>

namespace dyntrace::fasttp
{
    template<size_t levels = 6>
    class code_allocator
    {
        class page
        {
        public:
            static constexpr size_t size = PAGE_SIZE;
            static constexpr size_t block = size >> levels;
            explicit page(void* base)
                : _base{reinterpret_cast<uintptr_t>(base)}
            {
                if(mmap(base, size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED, -1, 0) == MAP_FAILED)
                {
                    throw std::bad_alloc{};
                }
                _tree[1] = true;
            }
            ~page() noexcept
            {
                munmap(reinterpret_cast<void*>(_base), size);
            }

            void* base() const noexcept
            {
                return reinterpret_cast<void*>(_base);
            }

            size_t free() const noexcept
            {
                for(size_t i = 1; i < _tree.size(); ++i)
                {

                }
            }

            bool full() const noexcept
            {
                return free() == 0;
            }

            bool empty() const noexcept
            {
                return free() == size;
            }

            void* malloc(size_t size)
            {
                return nullptr;
            }

            void free(void* ptr)
            {

            }

        private:
            static constexpr size_t level(size_t idx)
            {
            }

            std::bitset<(1 << levels)> _tree{};
            uintptr_t _base;
        };
    public:

    private:
    };
}

#endif