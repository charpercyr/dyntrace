#ifndef DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_


#include <capstone.h>

#include <vector>

namespace dyntrace::fasttp
{
    class out_of_line
    {
    public:

        explicit out_of_line(const void* code) noexcept;
        ~out_of_line() noexcept;

        void write(void* target);

        size_t size() const noexcept;
    private:
        csh _handle;
        std::vector<cs_insn*> _insns;
    };
}

#endif