#ifndef DYNTRACE_FASTTP_ARCH_X86_64_CODE_ALLOCATOR_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_CODE_ALLOCATOR_HPP_

#include "code_ptr.hpp"

#include "dyntrace/process/process.hpp"
#include "dyntrace/util/integer_range.hpp"

#include <array>
#include <list>
#include <memory>
#include <optional>
#include <unordered_map>
#include <sys/user.h>


namespace dyntrace::fasttp
{
    using constraint = std::array<std::optional<uint8_t>, 4>;

    class code_allocator
    {
    public:

        ~code_allocator() noexcept;

        code_ptr alloc(code_ptr from, size_t size, const constraint& c = {});
        void free(code_ptr ptr, size_t size) noexcept;

    private:

        void add_free(const address_range& range) noexcept;
        void remove_free(const address_range& range) noexcept;

        std::list<dyntrace::address_range> _free;
        std::unordered_map<code_ptr, size_t, code_ptr::hash> _refcount;
    };
}

#endif