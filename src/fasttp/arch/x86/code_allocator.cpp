#include "code_allocator.hpp"

#include "dyntrace/fasttp/error.hpp"

#include <sys/mman.h>

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

    template<typename Int, typename Int2>
    auto add_no_overflow(Int a, Int2 b)
    {
        using Ret = decltype(a + b);
        if(b > 0 && std::numeric_limits<Ret>::max() - b < a)
            return std::numeric_limits<Ret>::max();
        else if(b < 0 && std::numeric_limits<Ret>::min() - b > a)
            return std::numeric_limits<Ret>::min();
        else
            return a + b;
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

    code_ptr find_address(code_ptr from, size_t size, const constraint &c, const address_range &range)
    {
        if(!range)
            return {};
        auto off = make_offset_range(from, range);
        auto off_start_data = reinterpret_cast<uint8_t*>(&off.start);
        for(size_t i = 0; i < 4; ++i)
            off_start_data[i] = c[i].value_or(off_start_data[i]);
        if(range.contains(address_range{from.as_int() + off.start, from.as_int() + off.start + size}))
            return from + off.start;
        else
            return {};
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

    std::pair<code_ptr, code_ptr> get_pages(code_ptr ptr, size_t size) noexcept
    {
        return {ptr & PAGE_MASK, (ptr + size - 1) & PAGE_MASK};
    };
}

code_allocator::~code_allocator() noexcept
{
    for(const auto& f : _refcount)
        dealloc_page(f.first);
}

code_ptr code_allocator::alloc(code_ptr from, size_t size, const constraint &c)
{
    auto offset_range = make_offset_range(c);
    auto constraint_range = address_range{
        add_no_overflow(from.as_int(), offset_range.start),
        add_no_overflow(from.as_int(), offset_range.end)
    };
    // We usually can't mmap at 0, we'll mmap over 1M just to be sure.
    if(constraint_range.start < 1_M)
        constraint_range.start = 1_M;
    code_ptr res;
    for(const auto& f :_free)
    {
        res = find_address(from, size, c, constraint_range.intersection(f));
        if(res)
            break;
    }
    if(!res)
    {
        auto free = process::process::this_process().create_memmap().free();
        for(const auto& f : free)
        {
            res = find_address(from, size, c, constraint_range.intersection(f));
            if(res)
                break;
        }
    }
    if(!res)
        return {};

    auto [first_page, last_page] = get_pages(res, size);

    for(auto i = first_page; i <= last_page; i += PAGE_SIZE)
    {
        auto it = _refcount.find(i);
        if(it != _refcount.end())
            ++it->second;
        else
        {
            alloc_page(i);
            _refcount.insert(std::make_pair(i, 1));
            add_free({i.as_int(), i.as_int() + PAGE_SIZE});
        }
    }
    remove_free({res.as_int(), res.as_int() + size});
    return res;
}

void code_allocator::free(code_ptr ptr, size_t size) noexcept
{
    auto [first_page, last_page] = get_pages(ptr, size);

    add_free({ptr.as_int(), ptr.as_int() + size});

    for(auto i = first_page; i <= last_page; i += PAGE_SIZE)
    {
        auto it = _refcount.find(i);
        if(it != _refcount.end())
        {
            --it->second;
            if(it->second == 0)
            {
                dealloc_page(it->first);
                _refcount.erase(it);
                remove_free({i.as_int(), i.as_int() + PAGE_SIZE});
            }
        }
    }
}

void code_allocator::add_free(const address_range &range) noexcept
{
    auto it = _free.begin();
    for(; it != _free.end(); ++it)
    {
        auto cur = it;
        if(it->start == range.end)
        {
            it->start = range.start;
            if(it != _free.begin())
            {
                --it;
                if(it->end == range.start)
                {
                    auto start = it->start;
                    _free.erase(it);
                    cur->start = start;
                }
            }
            return;
        }
        else if(it->end == range.start)
        {
            it->end = range.end;
            ++it;
            if(it != _free.end() && it->start == range.end)
            {
                auto end = it->end;
                _free.erase(it);
                cur->end = end;
            }
            return;
        }
        else if(range.start > it->end)
        {
            ++it;
            break;
        }
    }
    _free.insert(it, range);
}

void code_allocator::remove_free(const address_range &range) noexcept
{
    for(auto it = _free.begin(); it != _free.end(); ++it)
    {
        if(it->contains(range))
        {
            address_range before(it->start, range.start);
            address_range after(it->end, range.end);
            _free.erase(it++);
            if(before)
                _free.insert(it, before);
            if(after)
                _free.insert(it, after);
            break;
        }
    }
}
