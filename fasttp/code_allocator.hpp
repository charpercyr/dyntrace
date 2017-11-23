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

        code_allocator(const code_allocator&) = delete;
        code_allocator& operator=(const code_allocator&) = delete;

        explicit code_allocator(std::shared_ptr<const process::process> proc) noexcept
            : _proc{std::move(proc)} {}
        ~code_allocator() noexcept;

        void* alloc(const address_range& range, size_t size);
        void free(void* ptr);

        struct deleter
        {
            code_allocator* _alloc;

            void operator()(void* ptr)
            {
                _alloc->free(ptr);
            }
        };
        using unique_ptr = std::unique_ptr<void, deleter>;

        unique_ptr make_unique(const address_range& range, size_t size)
        {
            return unique_ptr{alloc(range, size), deleter{this}};
        }

        size_t size() const noexcept;

    private:
        std::shared_ptr<const process::process> _proc;
        std::unordered_set<void*> _mem;
    };
}

#endif