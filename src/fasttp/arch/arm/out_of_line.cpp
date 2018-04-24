#include "out_of_line.hpp"

#include "dyntrace/util/util.hpp"

#include <capstone/capstone.h>

using namespace dyntrace::fasttp;

namespace
{
    enum class insn_type
    {
        normal,
        b,
        bl,
        pc_rel
    };

    insn_type categorize(uint32_t insn)
    {
        // TODO
        return insn_type::normal;
    }

    uint32_t make_jmp_back(uint32_t addr_off, bool up = false)
    {
        /*                                 cond -- I P U B W L Rn   Rd   Off*/
        static constexpr uint32_t insn = 0b1110'01'0'0'0'0'0'1'1111'1111'000000000000;
        static constexpr uint32_t sign = 0b0000'00'0'0'1'0'0'0'0000'0000'000000000000;
        static constexpr uint32_t mask = 0b0000'00'0'0'0'0'0'0'0000'0000'111111111111;
        dyntrace_assert(addr_off < 4096);
        return insn | (up ? sign : 0) | (addr_off & mask);
    }

    void make_normal(uint32_t(&target)[4], code_ptr insn)
    {
        target[0] = *insn.as<uint32_t*>();
    }

    void make_b(uint32_t(&target)[4], code_ptr insn)
    {
        
    }

    void make_bl(uint32_t(&target)[4], code_ptr insn)
    {
        
    }

    void make_pc_rel(uint32_t(&target)[4], code_ptr insn)
    {
        
    }
}

out_of_line::out_of_line(code_ptr code)
    : _code{code}
{
    switch(categorize(*code.as<uint32_t*>()))
    {
    case insn_type::normal:
        make_normal(_insns, code);
        _n = 2;
        break;
    case insn_type::b:
        make_b(_insns, code);
        _n = 2;
        break;
    case insn_type::bl:
        make_bl(_insns, code);
        _n = 4;
        break;
    case insn_type::pc_rel:
        make_pc_rel(_insns, code);
        _n = 3;
        break;
    }
}

size_t out_of_line::size() const
{
    return _n*4;
}

void out_of_line::write(buffer_writer w)
{
    _insns[_n - 1] = make_jmp_back(8 + _n*4);
    w.write_bytes(_insns, size());
}