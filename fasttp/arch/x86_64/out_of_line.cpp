#include "out_of_line.hpp"

#include <cstring>
#include <util/util.hpp>

#include "jmp.hpp"

using namespace dyntrace::fasttp;

namespace
{
    std::unique_ptr<instruction> make_instruction(cs_insn* insn)
    {
        // TODO weird rel8 branches (loop, jecxz, ...)
        uint8_t op = insn->bytes[0];
        // jmp rel8, jmp rel32, call rel32
        if(op == 0xe8 || op == 0xe9 || op == 0xeb)
            return std::make_unique<relative_branch>(insn);
        // j[cond] rel8
        else if((op & 0xf0) == 0x70)
            return std::make_unique<relative_cond_branch>(insn);
        // 0x0f j[cond] rel32
        else if(op == 0x0f)
        {
            op = insn->bytes[1];
            if((op & 0xf0) == 0x80)
                return std::make_unique<relative_cond_branch>(insn);
        }
        else
        {
            for(uint8_t i = 0; i < insn->detail->x86.op_count; ++i)
            {
                if(insn->detail->x86.operands[i].type == X86_OP_MEM)
                {
                    if(insn->detail->x86.operands[i].mem.base == X86_REG_RIP)
                        return std::make_unique<ip_relative_instruction>(insn);
                }
            }
        }
        return std::make_unique<instruction>(insn);
    }
}

instruction::~instruction()
{
    cs_free(_insn, 1);
}

uint8_t instruction::size() const noexcept
{
    return _insn->size;
}

void instruction::write(code_ptr to) const noexcept
{
    memcpy(to.as_ptr(), _insn->bytes, _insn->size);
}

uint8_t relative_branch::size() const noexcept
{
    return 4 + op_size();
}

void relative_branch::write(code_ptr to) const noexcept
{
    write_op(to);

    int32_t rel = displacement();
    uintptr_t target = insn()->address + insn()->size + rel;
    rel = calc_jmp(to.as_int(), target, size()).value();
    memcpy((to + op_size()).as_ptr(), &rel, 4);
}

uint8_t relative_branch::op_size() const noexcept
{
    return 1;
}

void relative_branch::write_op(code_ptr to) const noexcept
{
    *to.as<uint8_t*>() = 0xe9;
}

int32_t relative_branch::displacement() const noexcept
{
    if(insn()->size == 2)
    {
        return static_cast<int32_t>(insn()->bytes[1]);
    }
    else
    {
        return *reinterpret_cast<const int32_t*>(insn()->bytes + 1);
    }
}

uint8_t relative_cond_branch::op_size() const noexcept
{
    return 2;
}

void relative_cond_branch::write_op(code_ptr to) const noexcept
{
    *to.as<uint8_t*>() = 0x0f;
    if(insn()->size == 2)
    {
        *((to + 1).as<uint8_t*>()) = insn()->bytes[0] + 0x10;
    }
    else
    {
        *((to + 1).as<uint8_t*>()) = insn()->bytes[1];
    }
}

int32_t relative_cond_branch::displacement() const noexcept
{
    if(insn()->size == 2)
    {
        return static_cast<int32_t>(insn()->bytes[1]);
    }
    else
    {
        return *reinterpret_cast<const int32_t*>(insn()->bytes + 1);
    }
}

void ip_relative_instruction::write(code_ptr to) const noexcept
{
    uintptr_t disp_diff_bits = 0;
    for(uintptr_t i = 0; i < insn()->detail->x86.op_count; ++i)
    {
        if(insn()->detail->x86.operands[i].type == X86_OP_IMM)
            disp_diff_bits += insn()->detail->x86.operands[i].size;
    }
    uintptr_t disp_idx = insn()->size - 4 - (disp_diff_bits + 7) / 8;

    memcpy(to.as_ptr(), insn()->bytes, insn()->size);
    int32_t disp;
    memcpy(&disp, insn()->bytes + disp_idx, 4);

    uintptr_t target = insn()->address + disp_idx + 4 + disp;
    disp = calc_jmp(to.as_int(), target, disp_idx + 4).value();
    memcpy((to + disp_idx).as_ptr(), &disp, 4);
}

out_of_line::out_of_line(code_ptr _code) noexcept
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
    cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t count = 0;

    auto code = _code.as<const uint8_t*>();
    auto addr = _code.as_int();
    size_t size = 15;
    cs_insn* insn = cs_malloc(_handle);

    while(cs_disasm_iter(_handle, &code, &size, &addr, insn) && count < 5)
    {
        count += insn->size;
        _insns.push_back(make_instruction(insn));
        insn = cs_malloc(_handle);
        size = 15;
    }

    cs_free(insn, 1);
}

out_of_line::~out_of_line() noexcept
{
    cs_close(&_handle);
}

std::vector<redirect_handle> out_of_line::write(arch_context& ctx, code_ptr at, handler&& h)
{
    std::vector<redirect_handle> redirects;
    bool first = true;
    for(const auto& insn : _insns)
    {
        if(first)
            first = false;
        else
        {
            redirects.push_back(ctx.add_redirect(insn->address(), at, std::move(h)));
        }
        insn->write(at);
        at += insn->size();
    }
    return redirects;
}

size_t out_of_line::size() const noexcept
{
    size_t res = 0;
    for(const auto& insn : _insns)
        res += insn->size();
    return res;
}