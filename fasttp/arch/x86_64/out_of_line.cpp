#include "out_of_line.hpp"

#include "jmp.hpp"

#include <cstring>

using namespace dyntrace::fasttp;

namespace
{
    class instruction
    {
    public:
        instruction(cs_insn* insn)
            : _insn {insn} {}
        virtual ~instruction() = default;

        virtual size_t size() const noexcept
        {
            return _insn->size;
        }

        virtual void write(void* to) const noexcept
        {
            memcpy(to, _insn->bytes, _insn->size);
        }

    protected:

        const cs_insn* inner() const noexcept
        {
            return _insn;
        }

    private:
        const cs_insn* _insn;
    };

    struct relative_jmp : instruction
    {
        using instruction::instruction;

        size_t size() const noexcept override
        {
            return 5;
        }

        void write(void* to) const noexcept override
        {
            
        }
    };
}

namespace
{
    size_t insn_size(csh handle, cs_insn* insn) noexcept
    {
        // TODO JMP
        return insn->size;
    }

    void* write_insn(csh handle, cs_insn* insn, void* to)
    {
        // TODO JMP
        memcpy(to, insn->bytes, insn->size);
        return reinterpret_cast<uint8_t*>(to) + insn->size;
    }
}

out_of_line::out_of_line(const void *_code) noexcept
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
    cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t count = 0;

    auto code = reinterpret_cast<const uint8_t*>(_code);
    auto addr = reinterpret_cast<uintptr_t>(_code);
    size_t size = 15;
    cs_insn* insn = cs_malloc(_handle);

    while(cs_disasm_iter(_handle, &code, &size, &addr, insn) && count < 5)
    {
        count += insn->size;
        _insns.push_back(insn);
        insn = cs_malloc(_handle);
        size = 15;
    }

    cs_free(insn, 1);
}

out_of_line::~out_of_line() noexcept
{
    for(auto insn : _insns)
    {
        cs_free(insn, 1);
    }
    cs_close(&_handle);
}

void out_of_line::write(void *target)
{
    auto at = reinterpret_cast<uint8_t*>(target);
    for(auto insn : _insns)
    {
        at = reinterpret_cast<uint8_t*>(write_insn(_handle, insn, at));
    }
}

size_t out_of_line::size() const noexcept
{
    size_t res = 0;
    for(auto insn : _insns)
        res += insn_size(_handle, insn);
    return res;
}