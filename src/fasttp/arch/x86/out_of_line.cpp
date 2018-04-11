#include "out_of_line.hpp"

#include "jmp.hpp"

#include "context.hpp"

using namespace dyntrace::fasttp;

namespace
{
    constexpr uint8_t jmp8_op = 0xeb;
    constexpr uint8_t jmp32_op = 0xe9;
    constexpr uint8_t call_op = 0xe8;
    constexpr uint8_t lea_op = 0x8d;

    std::unique_ptr<instruction> make_instruction(cs_insn* insn)
    {
        // TODO weird rel8 branches (loop, jecxz, ...)
        uint8_t op = insn->bytes[0];
        // jmp rel8, jmp rel32, call rel32
        if(op == jmp8_op || op == jmp32_op || op == call_op)
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

#ifdef __i386__

    const std::unordered_map<std::string, uint8_t> reg_name_ids = {
        {"ax", 0},
        {"cx", 1},
        {"dx", 2},
        {"bx", 3},
        {"sp", 4},
        {"di", 6},
        {"si", 7},
    };

    uint8_t get_register(const std::string& thunk)
    {
        auto i = thunk.find_last_of('.');
        return reg_name_ids.at(thunk.substr(i + 1));
    }

    auto init_thunks()
    {
        std::regex thunk_pattern{".*\\.get_pc_thunk\\.(.*)"};
        std::unordered_map<uintptr_t, uint8_t> res;
        auto symtab = dyntrace::process::process::this_process().elf().get_section(".symtab");
        if(symtab.valid())
        {
            for(auto&& sym : symtab.as_symtab())
            {
                if(std::regex_match(sym.get_name(), thunk_pattern))
                {
                    res.insert(std::make_pair(dyntrace::process::process::this_process().base() + sym.get_data().value, get_register(sym.get_name())));
                }
            }
        }
        return res;
    }

    std::optional<uint8_t> is_thunk(uintptr_t addr)
    {
        static const auto thunks = init_thunks();

        auto it = thunks.find(addr);
        if(it != thunks.end())
            return it->second;
        else
            return {};
    }

    void write_lea(buffer_writer& w, uint8_t id, uintptr_t orig)
    {
        uint8_t modrm = uint8_t{0b1000'0000} | (id << 3) | (id << 0);
        int32_t disp = orig - w.ptr().as_int();
        w.write(lea_op);
        w.write(modrm);
        w.write(disp);
    }

#endif // __i386__

    void remove_used_reg(std::unordered_set<x86_reg>& free, x86_reg reg)
    {
        switch(reg)
        {
            case X86_REG_AL:
            case X86_REG_AH:
            case X86_REG_AX:
            case X86_REG_EAX:
            case X86_REG_RAX:
                free.erase(X86_REG_RAX);
                break;
            case X86_REG_CL:
            case X86_REG_CH:
            case X86_REG_CX:
            case X86_REG_ECX:
            case X86_REG_RCX:
                free.erase(X86_REG_RCX);
                break;
            case X86_REG_DL:
            case X86_REG_DH:
            case X86_REG_DX:
            case X86_REG_EDX:
            case X86_REG_RDX:
                free.erase(X86_REG_RDX);
                break;
        case X86_REG_BL:
        case X86_REG_BH:
        case X86_REG_BX:
        case X86_REG_EBX:
        case X86_REG_RBX:
                free.erase(X86_REG_RBX);
                break;
            default:
                break;
        }
    }

    x86_reg find_free_reg(const cs_insn* insn)
    {
        std::unordered_set<x86_reg> free = {
            X86_REG_RAX, X86_REG_RCX, X86_REG_RDX, X86_REG_RBX
        };
        auto x86 = &insn->detail->x86;
        for(size_t i = 0; i < x86->op_count; ++i)
        {
            if(x86->operands[i].type == X86_OP_REG)
            {
                remove_used_reg(free, x86->operands[i].reg);
            }
            else if(x86->operands[i].type == X86_OP_MEM)
            {
                remove_used_reg(free, static_cast<x86_reg>(x86->operands[i].mem.base));
                remove_used_reg(free, static_cast<x86_reg>(x86->operands[i].mem.index));
            }
        }
        return *free.begin();
    }

    const std::unordered_map<x86_reg, uint8_t> reg_capstone_ids = {
        {X86_REG_RAX, 0},
        {X86_REG_RCX, 1},
        {X86_REG_RDX, 2},
        {X86_REG_RBX, 3},
    };

    uint16_t patched_ip_rel_size(uint16_t size)
    {
        return size + 8;
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

void instruction::write(buffer_writer &writer) const
{
    writer.write_bytes(_insn->bytes, _insn->size);
}

uint8_t relative_branch::size() const noexcept
{
    return 4 + op_size();
}

void relative_branch::write(buffer_writer &writer) const noexcept
{
    int32_t rel = displacement();
    uintptr_t target = insn()->address + insn()->size + rel;
    rel = calc_jmp(writer.ptr().as_int(), target, size()).value();

    write_op(writer);
    writer.write(rel);

#ifdef __i386__
    // Patch call get_pc_thunk.<reg> (get eip).
    if(insn()->bytes[0] == call_op)
    {
        if(auto _id = is_thunk(target))
        {
            write_lea(writer, _id.value(), insn()->address + insn()->size);
        }
    }
#endif // __i386__
}

uint8_t relative_branch::op_size() const noexcept
{
    return 1;
}

void relative_branch::write_op(buffer_writer &writer) const noexcept
{
    writer.write(insn()->bytes[0] == 0xe8 ? uint8_t{0xe8} : uint8_t{0xe9});
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

void relative_cond_branch::write_op(buffer_writer &writer) const noexcept
{
    writer.write(uint8_t{0x0f});
    if(insn()->size == 2)
        writer.write(insn()->bytes[0] + 0x10);
    else
        writer.write(insn()->bytes[1]);
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

uint8_t ip_relative_instruction::size() const noexcept
{
    return patched_ip_rel_size(insn()->size);
}

void ip_relative_instruction::write(buffer_writer &writer) const
{
    auto free_reg = find_free_reg(insn());
    auto reg_id = reg_capstone_ids.at(free_reg);
    uintptr_t disp_diff_bits = 0;
    for(uintptr_t i = 0; i < insn()->detail->x86.op_count; ++i)
    {
        if(insn()->detail->x86.operands[i].type == X86_OP_IMM)
            disp_diff_bits += insn()->detail->x86.operands[i].size;
    }
    uintptr_t disp_idx = insn()->size - 4 - (disp_diff_bits + 7) / 8;

    auto disp = *reinterpret_cast<const int32_t*>(insn()->bytes + disp_idx);
    uintptr_t target = insn()->address + disp_idx + 4 + disp;

    uint8_t modrm = insn()->bytes[disp_idx - 1];
    modrm = (modrm & 0b00'111'000) | (reg_id & 0b00'000'111);

    writer.write(uint8_t(0x50 + reg_id)); // push %reg
    writer.write(uint8_t(0x48)); // REX.W
    writer.write(uint8_t(0xb8 + reg_id)); // MOVABS ???, %reg
    writer.write(target);
    writer.write_bytes(insn()->bytes, disp_idx - 1);
    writer.write(modrm);
    writer.write_bytes(insn()->bytes + disp_idx + 4, insn()->size - disp_idx - 4);
    writer.write(uint8_t(0x58 + reg_id));
}

out_of_line::out_of_line(code_ptr _code) noexcept
{
    cs_open(CS_ARCH_X86, CS_MODE_64, &_handle);
    cs_option(_handle, CS_OPT_DETAIL, CS_OPT_ON);

    size_t count = 0;

    auto code = _code.as<const uint8_t*>();
    uint64_t addr = _code.as_int();
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

void out_of_line::write(buffer_writer& writer, write_callback callback)
{
    for(const auto& insn : _insns)
    {
        if(callback)
            callback(code_ptr{insn->address()}, writer.ptr());
        insn->write(writer);
    }
}

size_t out_of_line::ool_size() const noexcept
{
    size_t res = 0;
    for(const auto& insn : _insns)
        res += insn->insn()->size;
    return res;
}

size_t out_of_line::size() const noexcept
{
    size_t res = 0;
    for(const auto& insn : _insns)
        res += insn->size();
    return res;
}