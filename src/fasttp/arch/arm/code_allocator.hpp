#ifndef DYNTRACE_FASTTP_ARCH_ARM_CODE_ALLOCATOR_HPP_
#define DYNTRACE_FASTTP_ARCH_ARM_CODE_ALLOCATOR_HPP_

#include <bitset>
#include <optional>
#include <unordered_map>

#include "dyntrace/process/process.hpp"
#include "dyntrace/util/integer_range.hpp"
#include "dyntrace/util/util.hpp"

#include <sys/mman.h>

namespace dyntrace::fasttp
{
    template<size_t alloc_shift>
    class code_allocator
    {
    public:
        static inline constexpr size_t alloc_size = 1 << alloc_shift;
        static inline constexpr size_t page_size = 4096; // True on (most) ARM 32-bit
        static inline constexpr size_t slab_bits = page_size / alloc_size;
        static_assert(alloc_shift > 0 && alloc_size < page_size);

        void* alloc(size_t size, const std::optional<address_range>& range = std::nullopt)
        {
            dyntrace_assert(size <= page_size);
            size_t n_slots = ceil_div(size, alloc_size);
            for(auto [p, sl] : _partial_slabs)
            {
                if(range && !range.value().contains(address_range{p, p + page_size}))
                    continue;
                if(auto slot = sl.alloc(n_slots); slot != -1)
                {
                    auto ptr = calc_address(p, slot);
                    if(sl.full())
                    {
                        _full_slabs.emplace(p, sl);
                        _partial_slabs.erase(p);
                        return ptr;
                    }
                }
            }
            void* ptr = nullptr;
            if(range)
            {
                auto page = find_page(range.value());
                if(!page)
                    return nullptr;
                ptr = mmap(
                    reinterpret_cast<void*>(page), page_size,
                    PROT_EXEC | PROT_WRITE | PROT_READ,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                    -1, 0
                );
            }
            else
            {
                ptr = mmap(
                    nullptr, page_size,
                    PROT_EXEC | PROT_WRITE | PROT_READ,
                    MAP_ANONYMOUS | MAP_PRIVATE | MAP_FIXED,
                    -1, 0
                );
            }
            if(!ptr)
                return nullptr;
            slab sl;
            auto slot = sl.alloc(n_slots);
            if(slot == -1)
            {
                // Should not happen
                munmap(ptr, page_size);
                return nullptr;
            }
            if(sl.full())
                _full_slabs.emplace(ptr, sl);
            else
                _partial_slabs.emplace(ptr, sl);
            return calc_address(reinterpret_cast<uintptr_t>(ptr), slot);
        }
        void free(void* ptr, size_t size)
        {
            size_t n = ceil_div(size, alloc_size);
        }

    private:

        void* calc_address(uintptr_t base, uintptr_t slot)
        {
            dyntrace_assert(slot < slab_bits);
            return reinterpret_cast<void*>(base + slot * alloc_size);
        }

        uintptr_t find_page(const address_range& range)
        {
            auto free = process::process::this_process().create_memmap().free();
            for(auto&& z : free)
            {
            }
        }

        struct slab
        {
            std::bitset<slab_bits> taken;

            size_t alloc(size_t n)
            {
                dyntrace_assert(n < slab_bits);
                for(size_t i = 0; i < slab_bits - n + 1; ++i)
                {
                    bool good = true;
                    for(size_t j = i; j < n; ++j)
                    {
                        if(taken[j])
                        {
                            good = false;
                            break;
                        }
                    }
                    if(good)
                    {
                        for(size_t j = i; j < n; ++j)
                        {
                            taken.set(j);
                        }
                        return i;
                    }
                }
                return -1;
            }
            void free(size_t n, size_t s)
            {
                dyntrace_assert(n + s <= slab_bits);
                for(size_t i = n; i < n + s; ++i)
                {
                    dyntrace_assert(taken[i]);
                    taken.set(i, false);
                }
            }

            bool full() const
            {
                return taken.count() == slab_bits;
            }
            bool empty() const
            {
                return taken.count() == 0;
            }
        };
        std::unordered_map<uintptr_t, slab> _partial_slabs;
        std::unordered_map<uintptr_t, slab> _full_slabs;
    };
}

#endif