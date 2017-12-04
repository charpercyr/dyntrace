#include "error.hpp"
#include "fasttp.hpp"

using namespace dyntrace::fasttp;

tracepoint::~tracepoint()
{
    if(_auto_remove)
        remove();
}

void tracepoint::remove()
{
    _auto_remove = false;
    if(_impl)
    {
        _ctx->remove(_impl->location());
        _impl = nullptr;
    }
}

context::context(std::shared_ptr<const process::process> proc)
    : _proc{std::move(proc)}
{
    try
    {
        auto dw = _proc->dwarf();
        for (const auto &cu : dw.compilation_units())
        {
            for (const auto &sp : cu.root())
            {
                if (sp.tag == dwarf::DW_TAG::subprogram)
                {
                    for (const auto &bb : sp)
                    {
                        // Custom tag for basic block
                        if (static_cast<int>(bb.tag) == 0x1001)
                        {
                            auto base = bb[dwarf::DW_AT::low_pc].as_address();
                            auto size = bb[dwarf::DW_AT::high_pc].as_uconstant();
                            _basic_blocks.push_back({base, base + size});
                        }
                    }
                }
            }
        }
    }
    catch(const std::exception& e)
    {
        // No basic block info
    }
}

context::~context() = default;

tracepoint context::create(const location &loc, handler &&handler, options ops)
{
    auto tracepoints = _tracepoints.lock();
    void* addr = loc.resolve(*_proc);
    if(tracepoints->find(addr) != _tracepoints->end())
    {
        throw fasttp_error{"Tracepoint already exists at " + to_hex_string(addr)};
    }
    auto it = tracepoints->insert(std::make_pair(addr, std::make_unique<arch_tracepoint>(addr, this, std::move(handler), ops))).first;
    return tracepoint{it->second.get(), this, !flag(ops, options::disable_auto_remove)};
}

void context::remove(void *ptr)
{
    auto tracepoints = _tracepoints.lock();
    auto it = tracepoints->find(ptr);
    if(it == tracepoints->end())
    {
        throw fasttp_error("Tracepoint " + to_hex_string(ptr) + " does not exist");
    }
    tracepoints->erase(it);
}