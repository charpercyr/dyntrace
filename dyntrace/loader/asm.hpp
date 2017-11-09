#ifndef DYNTRACE_LOADER_PRINTER_HPP_
#define DYNTRACE_LOADER_PRINTER_HPP_

#include <cstdint>
#include <vector>

namespace dyntrace
{
    namespace loader
    {
        std::vector<uint8_t> print_handler(uintptr_t from, uintptr_t to, uintptr_t handler);
    }
}


#endif