#include "fasttp.hpp"

#include "error.hpp"

#include "arch/asm.hpp"
#include <util/locked.hpp>

#include <cstdint>
#include <sys/mman.h>
#include <sys/user.h>

using namespace dyntrace::fasttp;

namespace
{
    class registry
    {
    public:
        struct entry
        {
            void *at{};
            code_allocator::unique_ptr handler_code{};
            handler h{};
            std::vector<uint8_t> old_code{};
        };

        void add(entry &&e)
        {
            auto reg = _reg.lock();
            reg->emplace(e.at, std::move(e));
        }

        void remove(void *at)
        {
            auto reg = _reg.lock();
            reg->erase(at);
        }

        auto get(void *at)
        {
            auto reg = _reg.lock();
            auto it = reg->find(at);
            if (it != reg->end())
            {
                return reg.lock_for<entry>(&it->second);
            }
            else
            {
                return reg.lock_for<entry>(nullptr);
            }
        }

        const entry *get(void *at) const
        {
            auto it = _reg->find(at);
            if (it != _reg->end())
            {
                return &it->second;
            }
            else
            {
                return nullptr;
            }
        }

    private:
        dyntrace::locked<std::unordered_map<void *, entry>> _reg;
    };

    registry reg;
    const registry &creg = reg;
}


namespace
{
    void handle_tracepoint(void *caller, const dyntrace::tracer::regs &r)
    {
        if (auto e = reg.get(caller))
        {
            e->h(caller, r);
        }
    }

    size_t bytes_to_copy(void *_code) noexcept
    {
        auto handle = create_csh();
        cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);

        auto code = reinterpret_cast<const uint8_t *>(_code);
        size_t size = 15;
        auto addr = reinterpret_cast<uintptr_t>(_code);
        size_t res = 0;

        auto insn = cs_malloc(handle);
        while (cs_disasm_iter(handle, &code, &size, &addr, insn) && res < branch_size)
        {
            res += insn->size;
            size = 15;
        }
        cs_free(insn, 1);
        cs_close(&handle);
        return res;
    }
}

void tracepoint::do_insert(handler &&h)
{
    registry::entry e;
    e.at = _at;
    e.h = std::move(h);

    auto at = reinterpret_cast<uint8_t *>(_at);

    e.old_code.resize(bytes_to_copy(_at));
    memcpy(e.old_code.data(), _at, e.old_code.size());

    e.handler_code = print_handler(*_alloc, at, at + e.old_code.size(), reinterpret_cast<void *>(handle_tracepoint),
                                   e.old_code);

    uintptr_t page = from_ptr(at) & PAGE_MASK;
    mprotect(to_ptr(page), PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE);
    print_branch(at, e.handler_code.get());
    mprotect(to_ptr(page), PAGE_SIZE, PROT_EXEC | PROT_READ);

    reg.add(std::move(e));
}

void tracepoint::do_remove()
{
    auto e = creg.get(_at);
    uintptr_t page = from_ptr(_at) & PAGE_MASK;
    mprotect(to_ptr(page), PAGE_SIZE, PROT_EXEC | PROT_READ | PROT_WRITE);
    safe_store(_at, *reinterpret_cast<const uintptr_t *>(e->old_code.data()));
    mprotect(to_ptr(page), PAGE_SIZE, PROT_EXEC | PROT_READ);
    reg.remove(e->at);
}

context::context(const std::shared_ptr<const process::process> &proc)
    : _proc{proc}, _alloc{proc}
{
    // Parse dwarf and get basic blocks
    auto sym_base = _proc->base();
    auto dw = _proc->dwarf();
    for(const auto& cu : dw.compilation_units())
    {
        for(const auto& sp: cu.root())
        {
            if(sp.tag == dwarf::DW_TAG::subprogram)
            {
                for(const auto& bb : sp)
                {
                    if(static_cast<int>(bb.tag) == 0x1001 && bb.has(dwarf::DW_AT::low_pc) && bb.has(dwarf::DW_AT::high_pc))
                    {
                        uintptr_t start = bb[dwarf::DW_AT::low_pc].as_address() + sym_base;
                        uintptr_t end = start + bb[dwarf::DW_AT::high_pc].as_uconstant();
                        _basic_blocks.push_back(address_range{start, end});
                    }
                }
            }
        }
    }
}

tracepoint context::create(const location& loc, handler &&h, bool auto_remove)
{
    void* at = loc.resolve(*_proc);
    for(const auto& bb : _basic_blocks)
    {
        auto uat = reinterpret_cast<uintptr_t>(at);
        if(bb.crosses(address_range{uat, uat + branch_size}))
        {
            throw fasttp_error("Cannot place tracepoint at 0x" + to_hex_string(uat) + ", crosses basic block 0x" + to_hex_string(bb.start) + "-0x" + to_hex_string(bb.end));
        }
    }
    return tracepoint{at, std::move(h), &_alloc, auto_remove};
}

void context::remove(tracepoint &tp)
{
    tp.remove();
}