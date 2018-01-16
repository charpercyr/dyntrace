#include "code_allocator.hpp"

#include <sys/mman.h>

#include <fasttp/error.hpp>

using namespace dyntrace;
using namespace dyntrace::fasttp;

using offset_range = integer_range<int32_t>;

namespace
{
    int32_t make_integer(const constraint& c, uint8_t val) noexcept
    {
        uint8_t res[4];
        for(size_t i = 0; i < 4; ++i)
        {
            res[i] = c[i].value_or(val);
        }
        return *reinterpret_cast<int32_t*>(res);
    }

    offset_range make_offset_range(const constraint& c) noexcept
    {
        int32_t start = make_integer(c, 0x00);
        int32_t end = make_integer(c, 0xff);
        if(!c[3])
        {
            start |= 0x8000'0000;
            end &= 0x7fff'ffff;
        }
        return offset_range{start, end};
    }

    offset_range make_offset_range(code_ptr from, const address_range& range)
    {
        int64_t start = range.start - from.as<int64_t>();
        int64_t end = range.end - from.as<int64_t>();
        if(
            start < std::numeric_limits<int32_t>::min() ||
            start > std::numeric_limits<int32_t>::max() ||
            end < std::numeric_limits<int32_t>::min() ||
            end > std::numeric_limits<int32_t>::max())
            return {};
        return offset_range{static_cast<int32_t>(start), static_cast<int32_t>(end)};
    }

    code_ptr find_address(const constraint &c, const offset_range &off)
    {
        if(!off)
            return {};
    }

    code_ptr get_page(code_ptr ptr) noexcept
    {
        return code_ptr{ptr.as_int() & PAGE_MASK};
    }

    void alloc_page(code_ptr ptr)
    {
        auto res = mmap(
            ptr.as_ptr(), PAGE_SIZE,
            PROT_EXEC | PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
            -1, 0
        );
        if(res != ptr.as_ptr())
            throw fasttp_error{"Could not allocate page " + to_hex_string(ptr.as_int())};
    }

    void dealloc_page(code_ptr ptr) noexcept
    {
        munmap(ptr.as_ptr(), PAGE_SIZE);
    }
}

code_allocator::~code_allocator()
{
    for(const auto& f : _refcount)
        dealloc_page(f.first);
}

code_ptr code_allocator::alloc(code_ptr from, size_t size, const constraint &c)
{
    auto range_around = address_range_around(from.as_int(), 2_G - 6 - size);
    auto offset_range = make_offset_range(c);
    auto constraint_range = address_range{from.as_int() + offset_range.start, from.as_int() + offset_range.end};
    code_ptr res;
    for(const auto& f :_free)
    {
        auto range = range_around.intersection(constraint_range).intersection(f);
        res = find_address(c, make_offset_range(from, range));
        if(res)
            break;
    }
    if(!res)
    {
        auto free = _proc->create_memmap().free();
        for(const auto& f : free)
        {
            auto range = range_around.intersection(constraint_range).intersection(f);
            res = find_address(c, make_offset_range(from, range));
            if(res)
                break;
        }
    }
    if(!res)
        return {};

    auto first_page = get_page(res);
    auto last_page = get_page(res + size - 1);

    for(auto i = first_page; i <= last_page; i += PAGE_SIZE)
    {
        auto it = _refcount.find(i);
        if(it != _refcount.end())
            ++it->second;
        else
        {
            alloc_page(i);
            _refcount.insert(std::make_pair(i, 1));
        }
    }

    return res;
}

void code_allocator::free(code_ptr ptr, size_t size) noexcept
{
}

