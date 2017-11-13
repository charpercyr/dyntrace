#include "asm.hpp"

#include <dyntrace/loader/error.hpp>
#include <util/util.hpp>

#include <cstring>

using namespace dyntrace::loader::target;

namespace
{
    int32_t calc_jmp(uintptr_t from, uintptr_t to)
    {
        from += 5;
        intptr_t diff = static_cast<intptr_t>(to) - static_cast<intptr_t>(from);
        if(diff > std::numeric_limits<int32_t>::max() || diff < std::numeric_limits<int32_t>::min())
        {
            using dyntrace::loader::loader_error;
            using dyntrace::to_hex_string;
            throw loader_error("Cannot jmp from 0x" + to_hex_string(from) + " to 0x" + to_hex_string(to));
        }
        return static_cast<int32_t>(diff);
    }
}

void x86_64::asm_printer::save_state()
{
    static constexpr size_t code_size = sizeof(code::save_state);
    memcpy(_to, code::save_state, code_size);
    _to += code_size;
}

void x86_64::asm_printer::restore_state()
{
    static constexpr size_t code_size = sizeof(code::restore_state);
    memcpy(_to, code::restore_state, code_size);
    _to += code_size;
}

void x86_64::asm_printer::call_handler(uintptr_t handler)
{
    static constexpr size_t code_size = sizeof(code::call_handler);
    memcpy(_to, code::call_handler, code_size);
    memcpy(_to + code::from_idx, &_from, 8);
    memcpy(_to + code::handle_idx, &handler, 8);
    _to += code_size;

}

void x86_64::asm_printer::jmp_back(uintptr_t off)
{
    static constexpr size_t code_size = sizeof(code::jmp_back);
    memcpy(_to, code::jmp_back, code_size);
    auto diff = calc_jmp(reinterpret_cast<uintptr_t>(_to), _from + off);
    memcpy(_to + code::to_idx, &diff, 4);
    _to += code_size;
}


void x86_64::asm_printer::write(void *code, size_t code_size)
{
    memcpy(_to, code, code_size);
    _to += code_size;
}