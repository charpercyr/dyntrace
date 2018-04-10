/**
 * Classes that represent the instruction that will be executed out of line.
 */
#ifndef DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_
#define DYNTRACE_FASTTP_ARCH_X86_64_PATCHER_HPP_

#include "buffer_writer.hpp"
#include "code_ptr.hpp"

#include "dyntrace/process/process.hpp"

#include <capstone/capstone.h>

#include <functional>
#include <memory>
#include <unordered_set>
#include <vector>

namespace dyntrace::fasttp
{
    /**
     * Base instruction. No patching is done.
     */
    class instruction
    {
    public:
        explicit instruction(cs_insn* insn)
                : _insn {insn} {}
        virtual ~instruction();

        virtual uint8_t size() const noexcept;

        virtual void write(buffer_writer &writer) const;

        uintptr_t address() const noexcept
        {
            return _insn->address;
        }

        const cs_insn* insn() const noexcept
        {
            return _insn;
        }

    private:
        cs_insn* _insn;
    };

    /**
     * jmp instruction. If it is a 2-byte jmp, the 5-byte version will be used. The offset is patched with the new location.
     */
    class relative_branch : public instruction
    {
    public:
        using instruction::instruction;

        uint8_t size() const noexcept override;

        void write(buffer_writer &writer) const noexcept override;

    protected:
        virtual uint8_t op_size() const noexcept;
        virtual void write_op(buffer_writer &writer) const noexcept;
        virtual int32_t displacement() const noexcept;
    };

    /**
     * j[cond] instruction. It is a relative branch. If it is 2-byte, the 6 bytes version will be used.
     */
    struct relative_cond_branch : relative_branch
    {
        using relative_branch::relative_branch;

    protected:
        uint8_t op_size() const noexcept override;
        void write_op(buffer_writer &writer) const noexcept override;
        int32_t displacement() const noexcept override;
    };

    /**
     * Instruction that addresses memory relative to the instruction pointer. The offset from rip is patched.
     */
    struct ip_relative_instruction : instruction
    {
        using instruction::instruction;

        uint8_t size() const noexcept override;
        void write(buffer_writer &writer) const;
    };

    /**
     * Constains all the out of line instructions.
     */
    class out_of_line
    {
    public:
        using write_callback = std::function<void(code_ptr, code_ptr)>;

        explicit out_of_line(code_ptr code) noexcept;
        ~out_of_line() noexcept;

        /**
         * Writes the instructions to the handler.
         * @param writer The byte writer
         * @param callback
         *          Function to call before writing an instruction.
         *          The first argument is the location, the second is the out-of-line equivalent location.
         * @return A vector of redirect handles. These handle are used when a trap is hit.
         */
        void write(buffer_writer &writer, write_callback callback);

        // Number of bytes replaced
        size_t ool_size() const noexcept;
        // Number of bytes produced
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