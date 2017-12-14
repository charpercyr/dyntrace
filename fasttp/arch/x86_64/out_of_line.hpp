#ifndef DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_

#include <fasttp/code_ptr.hpp>

#include <capstone.h>

#include <memory>
#include <vector>

#include "trap.hpp"

namespace dyntrace::fasttp
{
    class instruction
    {
    public:
        explicit instruction(cs_insn* insn)
                : _insn {insn} {}
        virtual ~instruction();

        virtual uint8_t size() const noexcept;

        virtual void write(code_ptr to) const noexcept;

        uintptr_t address() const noexcept
        {
            return _insn->address;
        }

    protected:

        const cs_insn* insn() const noexcept
        {
            return _insn;
        }

    private:
        cs_insn* _insn;
    };

    class relative_branch : public instruction
    {
    public:
        using instruction::instruction;

        uint8_t size() const noexcept override;

        void write(code_ptr to) const noexcept override;

    protected:
        virtual uint8_t op_size() const noexcept;
        virtual void write_op(code_ptr to) const noexcept;
        virtual int32_t displacement() const noexcept;
    };

    struct relative_cond_branch : relative_branch
    {
        using relative_branch::relative_branch;

    protected:
        uint8_t op_size() const noexcept override;
        void write_op(code_ptr to) const noexcept override;
        int32_t displacement() const noexcept override;
    };

    struct ip_relative_instruction : instruction
    {
        using instruction::instruction;

        void write(code_ptr to) const noexcept override;
    };

    class out_of_line
    {
    public:

        explicit out_of_line(code_ptr code) noexcept;
        ~out_of_line() noexcept;

        std::vector<trap_redirect_handle> write(code_ptr target);

        size_t size() const noexcept;

        const std::vector<std::unique_ptr<instruction>>& instructions() const noexcept
        {
            return _insns;
        }
    private:
        csh _handle;
        std::vector<std::unique_ptr<instruction>> _insns;
    };
}

#endif