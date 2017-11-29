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

size_t instruction::size() const noexcept
{
    return _insn->size;
}

void instruction::write(void* to) const noexcept
{
    memcpy(to, _insn->bytes, _insn->size);
}

size_t relative_branch::size() const noexcept
{
    return 5;
}

void relative_branch::write(void* to) const noexcept
{
    int32_t rel{0};
    if(insn()->size == 2)
        memcpy(&rel, insn()->bytes + 1, 1);
    else
        memcpy(&rel, insn()->bytes + 1, 4);
    uintptr_t target = insn()->address + insn()->size + rel;
    rel = calc_jmp(reinterpret_cast<uintptr_t>(to), target).value();
    uint8_t bytes[5] = {insn()->size == 2 ? uint8_t{0xe9} : insn()->bytes[0]};
    memcpy(bytes + 1, &rel, 4);
    memcpy(to, bytes, 5);
}

size_t relative_cond_branch::size() const noexcept
{
    return 6;
}

void relative_cond_branch::write(void *to) const noexcept
{
    int32_t rel{0};
    if(insn()->size == 2)
        memcpy(&rel, insn()->bytes + 1, 1);
    else
        memcpy(&rel, insn()->bytes + 2, 4);
    uintptr_t target = insn()->address + insn()->size + rel;
    rel = calc_jmp(reinterpret_cast<uintptr_t>(to), target, 6).value();
    uint8_t bytes[6] = {0x0f};
    if(insn()->size == 2)
        bytes[1] = insn()->bytes[0] + 0x10;
    else
        bytes[1] = insn()->bytes[1];
    memcpy(bytes + 2, &rel, 4);
    memcpy(to, bytes, 6);
}

void ip_relative_instruction::write(void *to) const noexcept
{
    int32_t rel{0};
    memcpy(&rel, insn()->bytes + insn()->size - 4, 4);
    uintptr_t target = insn()->address + insn()->size + rel;
    rel = calc_jmp(reinterpret_cast<uintptr_t>(to), target, insn()->size).value();
    memcpy(to, insn()->bytes, insn()->size - 4);
    memcpy(reinterpret_cast<uint8_t*>(to) + insn()->size - 4, &rel, 4);
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

void out_of_line::write(void *target)
{
    auto at = reinterpret_cast<uint8_t*>(target);
    for(const auto& insn : _insns)
    {
        insn->write(at);
        at += insn->size();
    }
    hexdump(target, size());
}

size_t out_of_line::size() const noexcept
{
    size_t res = 0;
    for(const auto& insn : _insns)
        res += insn->size();
    return res;
}