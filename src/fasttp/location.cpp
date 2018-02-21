#include "dyntrace/fasttp/location.hpp"

using namespace dyntrace::fasttp;

void* addr_location::resolve(const process::process &proc) const
{
    return addr;
}

void* symbol_location::resolve(const process::process &proc) const
{
    return reinterpret_cast<void*>(proc.get(name).value);
}