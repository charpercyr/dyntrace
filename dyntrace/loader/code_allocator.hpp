#ifndef DYNTRACE_DYNTRACE_LOADER_CODE_ALLOCATOR_HPP_
#define DYNTRACE_DYNTRACE_LOADER_CODE_ALLOCATOR_HPP_

#include <bitset>
#include <unordered_map>
#include <sys/user.h>

#include <process/process.hpp>
#include <util/util.hpp>

#include "error.hpp"

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
            static constexpr uintptr_t mask = PAGE_MASK;
            static constexpr uintptr_t slots = size / alignment;

            page(uintptr_t base)
                    : _base{base} {}

            size_t count() const noexcept
            {
                return _allocated.count();
            }

            bool full() const noexcept
            {
                return count() == slots;
            }

            bool empty() const noexcept
            {
                return count() == 0;
            }

            uintptr_t base() const noexcept
            {
                return _base;
            }

            uintptr_t begin() const noexcept
            {
                return _base;
            }

            uintptr_t end() const noexcept
            {
                return _base + size;
            }

            uintptr_t alloc() noexcept
            {
                for(size_t i = 0; i < slots; ++i)
                {
                    if(!_allocated[i])
                    {
                        _allocated[i] = true;
                        return _base + i * alignment;
                    }
                }
                return 0;
            }

            void free(uintptr_t ptr) noexcept
            {
                size_t idx = (ptr - _base) / alignment;
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

        void* alloc(range<uintptr_t> loc)
        {
            for(auto& [i, p] : _partial_pages)
            {
                if(loc.is_inside(p.begin()) && loc.is_inside(p.end()))
                {
                    auto ptr = p.alloc();
                    check_for_full(i, p);
                    return reinterpret_cast<void*>(ptr);
                }
            }
            auto p = new_page(loc);
            auto ptr = p.alloc();
            _partial_pages.insert(std::make_pair(p.base(), std::move(p)));
            check_for_full(p.base(), p);
            return reinterpret_cast<void*>(ptr);
        }

        void free(void* _ptr)
        {
            auto ptr = reinterpret_cast<uintptr_t>(_ptr);
            auto base = ptr & page::mask;

            auto it = _partial_pages.find(base);
            if(it != _partial_pages.end())
            {
                it->second.free(ptr);
                if(it->second.empty())
                {
                    _partial_pages.erase(base);
                    do_munmap(base);
                }
                return;
            }

            it = _full_pages.find(base);
            if(it != _full_pages.end())
            {
                it->second.free(ptr);
                if(it->second.empty())
                {
                    _partial_pages.insert(std::make_pair(base, std::move(it->second)));
                    _full_pages.erase(it);
                }
                return;
            }
            throw std::bad_alloc{};
        }

    private:

        void check_for_full(uintptr_t i, page &p)
        {
            if(p.full())
            {
                _full_pages.insert(std::make_pair(i, std::move(p)));
                _partial_pages.erase(i);
            }
        }

        page new_page(range<uintptr_t> loc)
        {
            auto free_map = _proc.create_memmap().free();
            for(const auto& z : free_map)
            {
                if(z.start != 0 && loc.is_inside(z.start))
                {
                    return page{do_mmap(z.start)};
                }
                if(loc.is_inside(z.end - page::size))
                {
                    return page{do_mmap(z.end - page::size)};
                }
            }
        }

        uintptr_t do_mmap(uintptr_t loc)
        {
            auto ptr = mmap(
                    reinterpret_cast<void*>(loc), page::size,
                    PROT_READ | PROT_WRITE | PROT_EXEC,
                    MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE, 0, -1);
            if(ptr == MAP_FAILED)
                throw std::bad_alloc{};
            return reinterpret_cast<uintptr_t>(ptr);
        }

        void do_munmap(uintptr_t loc)
        {
            munmap(reinterpret_cast<void*>(loc), page::size);
        }

        const process::process& _proc;
        std::unordered_map<uintptr_t, page> _partial_pages;
        std::unordered_map<uintptr_t, page> _full_pages;
    };
}

#endif