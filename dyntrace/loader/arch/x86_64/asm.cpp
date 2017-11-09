#include "asm.hpp"

#include <dyntrace/loader/error.hpp>
#include <util/util.hpp>

#include <cstring>

using namespace dyntrace::loader::target;

namespace
{
    int32_t calc_jmp(uintptr_t from, uintptr_t to)
    {
        intptr_t diff = static_cast<intptr_t>(to) - static_cast<intptr_t>(from) + 5;
        if(diff > std::numeric_limits<int32_t>::max() || diff < std::numeric_limits<int32_t>::min())
        {
            using dyntrace::loader::loader_error;
            using dyntrace::to_hex_string;
            throw loader_error("Cannot jmp from 0x" + to_hex_string(from) + " to 0x" + to_hex_string(to));
        }
        return static_cast<int32_t>(diff);
    }
}

void x86_64::write_code(uintptr_t from, uintptr_t to, uintptr_t handler) const noexcept
{
    auto pto = reinterpret_cast<uint8_t*>(to);

    memcpy(pto, code::data, code::code_size);
    memcpy(pto + code::from_idx, &from, sizeof(from));
    memcpy(pto + code::handler_idx, &handler, sizeof(handler));
    auto jmp = calc_jmp(from, to + code::jmp_idx + 4);
    memcpy(pto + code::jmp_idx, &handler, sizeof(jmp));
}