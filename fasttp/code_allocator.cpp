#include "code_allocator.hpp"

#include <sys/mman.h>
#include <sys/user.h>

using namespace dyntrace::fasttp;

code_allocator::~code_allocator() noexcept
{
    for(const auto& p : _mem)
        munmap(p, PAGE_SIZE);
}

namespace
{
    void* do_alloc(void* addr)
    {
        auto res = mmap(
            addr, PAGE_SIZE,
            PROT_READ | PROT_WRITE | PROT_EXEC,
            MAP_ANONYMOUS | MAP_FIXED | MAP_PRIVATE,
            -1, 0
        );
        if(res == MAP_FAILED)
            throw std::bad_alloc{};
        return res;
    }
}

void* code_allocator::alloc(const address_range& range, size_t size)
{
    if(size > PAGE_SIZE)
        throw std::bad_alloc{};
    auto fz = _proc->create_memmap().free();
    for(auto& z : fz)
    {
        void* ptr = nullptr;
        if(range.is_inside(z.start))
        {
            ptr = do_alloc(reinterpret_cast<void*>(z.start));
        }
        else if(range.is_inside(z.end - PAGE_SIZE))
        {
            ptr = do_alloc(reinterpret_cast<void*>(z.end - PAGE_SIZE));
        }
        else if(z.is_inside(range))
        {
            ptr = do_alloc(reinterpret_cast<void*>(range.start & PAGE_MASK + PAGE_SIZE));
        }
        if(ptr)
        {
            _mem.insert(ptr);
            return ptr;
        }
    }
    throw std::bad_alloc{};
}

void code_allocator::free(void *ptr)
{
    if(!ptr)
        return;
    auto it = _mem.find(ptr);
    if(it != _mem.end())
    {
        munmap(*it, PAGE_SIZE);
        _mem.erase(it);
    }
    else
        throw std::bad_alloc{};
}

size_t code_allocator::size() const noexcept
{
    return _mem.size() * PAGE_SIZE;
}