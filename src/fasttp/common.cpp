#include "dyntrace/fasttp/common.hpp"

#include "dyntrace/process/process.hpp"

namespace dyntrace::fasttp
{
    void* resolve(const std::string& loc)
    {
        auto sym = dyntrace::process::process::this_process().get(loc);
        return reinterpret_cast<void*>(sym.value);
    }
}