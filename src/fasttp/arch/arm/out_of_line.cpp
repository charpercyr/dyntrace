#include "out_of_line.hpp"

#include "dyntrace/util/util.hpp"

#include <capstone/capstone.h>

using namespace dyntrace::fasttp;

namespace
{
    enum class insn_category
    {
        normal,
        b,
        bl,
        pc_rel
    };

    insn_category categorize(uint32_t insn)
    {
        /*                                   cond --- L offset */
        static constexpr uint32_t b_mask = 0b0000'111'1'0000'0000'0000'0000'0000'0000;
        static constexpr uint32_t b_op   = 0b0000'101'0'0000'0000'0000'0000'0000'0000;
        static constexpr uint32_t bl_op  = 0b0000'101'1'0000'0000'0000'0000'0000'0000;
        /*                                    cond I P U B W L base s/d  imm*/
        static constexpr uint32_t pc_mask = 0b0000'1'1'0'0'1'0'1111'0000'0000'0000'0000;
        static constexpr uint32_t pc_op   = 0b0000'0'1'0'0'0'0'1111'0000'0000'0000'0000;

        if((insn & b_mask) == b_op)
            return insn_category::b;
        else if((insn & b_mask) == bl_op)
            return insn_category::bl;
        else if(((insn & pc_mask) == pc_op))
            return insn_category::pc_rel;
        return insn_category::normal;
    }

    uint8_t get_cond(uint32_t insn)
    {
        return (insn & 0xf000'0000) >> 28;
    }

    inline constexpr uint8_t lr_id = 14;
    inline constexpr uint8_t pc_id = 15;
    inline constexpr uint8_t cond_always = 0b1110;
    uint32_t make_ldr(uint8_t cond, uint16_t dst, uint16_t base, int16_t off)
    {
        /*                                 cond   -- I P U B W L Rn   Rd   Off*/
        static constexpr uint32_t insn   = 0b0000'01'0'1'0'0'0'1'0000'0000'0000'0000'0000;
        static constexpr uint32_t sign   = 0b0000'00'0'0'1'0'0'0'0000'0000'0000'0000'0000;
        static constexpr uint32_t o_mask = 0b0000'00'0'0'0'0'0'0'0000'0000'1111'1111'1111;
        static constexpr uint32_t dst_shift = 12;
        static constexpr uint32_t base_shift = 16;
        static constexpr uint32_t reg_mask = 0xf;
        static constexpr uint32_t cond_shift = 28;
        static constexpr uint32_t cond_mask = 0xf;
        bool up = off >= 0;
        off = up ? off : -off;
        dyntrace_assert(off < 4096);
        return
            insn |
            (uint32_t(cond & cond_mask) << cond_shift) |
            (up ? sign : 0) |
            (uint32_t(dst & reg_mask) << dst_shift) |
            (uint32_t(base & reg_mask) << base_shift) |
            (off & o_mask);
    }

    using insn_type = uint32_t[out_of_line::max_insn];

    size_t make_normal(insn_type& target, code_ptr code, uint32_t insn)
    {
        target[0] = insn;
        return 1;
    }

    inline constexpr uint32_t b_mask = 0x00ff'ffff;
    size_t make_b(insn_type& target, code_ptr code, uint32_t insn)
    {
        int32_t off = insn & b_mask;
        if(off & 0x0080'0000)
            off |= 0xff00'0000;
        target[2] = code.as_int() + 8 + off;;
        target[0] = make_ldr(get_cond(insn), pc_id, pc_id, 0);
        return 1;
    }

    size_t make_bl(insn_type& target, code_ptr code, uint32_t insn)
    {
        int32_t off = insn & b_mask;
        if(off & 0x0080'0000)
            off |= 0xff00'0000;
        target[3] = code.as_int() + 4;
        target[4] = code.as_int() + 8 + off;
        target[0] = make_ldr(get_cond(insn), lr_id, pc_id, 4);
        target[1] = make_ldr(get_cond(insn), pc_id, pc_id, 4);
        return 2;
    }

    size_t make_pc_rel(insn_type& target, code_ptr code, uint32_t insn)
    {
        // HOPE THAT THE INSTRUCTION IS NOT STR (no sensible compiler would ever do that)

        static constexpr uint32_t sign_mask = 0b0000'00'0'0'1'0'0'0'0000'0000'0000'0000'0000;
        static constexpr uint32_t off_mask = 0xfff;
        int32_t off = insn & off_mask;
        bool up = (insn & sign_mask) != 0;
        if(!up)
            off = -off;
        target[2] = *reinterpret_cast<uint32_t*>(code.as_int() + 8 + off);
        target[0] = insn & ~off_mask;
        return 1;
    }
}

out_of_line::out_of_line(code_ptr code)
    : _code{code}
{
    _insn = *code.as<uint32_t*>();
    switch(categorize(_insn))
    {
    case insn_category::normal:
        _n = 2;
        break;
    case insn_category::b:
        _n = 3;
        break;
    case insn_category::bl:
        _n = 5;
        break;
    case insn_category::pc_rel:
        _n = 3;
        break;
    }
    dyntrace_assert(_n <= max_insn);
}

size_t out_of_line::size() const
{
    return _n*4;
}

void out_of_line::write(buffer_writer w)
{
    insn_type insns{};
    auto cat = categorize(_insn);
    size_t jmp_idx;
    switch(cat)
    {
    case insn_category::normal:
        jmp_idx = make_normal(insns, _code, _insn);
        break;
    case insn_category::b:
        jmp_idx = make_b(insns, _code, _insn);
        break;
    case insn_category::bl:
        jmp_idx = make_bl(insns, _code, _insn);
        break;
    case insn_category::pc_rel:
        jmp_idx = make_pc_rel(insns, _code, _insn);
        break;
    }
    insns[jmp_idx] = make_ldr(cond_always, pc_id, pc_id, -(8 + (jmp_idx + 1)*4));
    w.write_bytes(insns, size());
}