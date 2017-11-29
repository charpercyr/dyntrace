#ifndef DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_


#include <capstone.h>

#include <memory>
#include <vector>

namespace dyntrace::fasttp
{
    class instruction
    {
    public:
        explicit instruction(cs_insn* insn)
                : _insn {insn} {}
        virtual ~instruction();

        virtual size_t size() const noexcept;

        virtual void write(void* to) const noexcept;

    protected:

        const cs_insn* insn() const noexcept
        {
            return _insn;
        }

    private:
        cs_insn* _insn;
    };

    struct relative_branch : instruction
    {
        using instruction::instruction;

        size_t size() const noexcept override;

        void write(void* to) const noexcept override;
    };

    struct relative_cond_branch : instruction
    {
        using instruction::instruction;

        size_t size() const noexcept override;

        void write(void* to) const noexcept override;
    };

    class out_of_line
    {
    public:

        explicit out_of_line(const void* code) noexcept;
        ~out_of_line() noexcept;

        void write(void* target);

        size_t size() const noexcept;
    private:
        csh _handle;
        std::vector<std::unique_ptr<instruction>> _insns;
    };
}

#endif