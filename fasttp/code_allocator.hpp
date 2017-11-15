#ifndef DYNTRACE_FASTTP_CODE_ALLOCATOR_HPP_
#define DYNTRACE_FASTTP_CODE_ALLOCATOR_HPP_

#include <memory>
#include <unordered_set>

#include <process/process.hpp>
#include <util/util.hpp>

namespace dyntrace::fasttp
{
    // TODO Better implementation
    class code_allocator
    {
    public:
        explicit code_allocator(const process::process& proc) noexcept
            : _proc{proc} {}
        ~code_allocator() noexcept;

        void* alloc(const address_range& range, size_t size);
        void free(void* ptr);

        auto make_unique(const address_range& range, size_t size)
        {
            auto deleter = [this](void* ptr)
            {
                this->free(ptr);
            };
            return std::unique_ptr<void, decltype(deleter)>(alloc(range, size), deleter);
        }

        size_t size() const noexcept;

    private:
        const process::process& _proc;
        std::unordered_set<void*> _mem;
    };
}

#endif