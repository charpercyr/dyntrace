#include "process.hpp"

#include <fcntl.h>

#include <util/flag.hpp>

using namespace dyntrace::process;

const elf::elf& process::elf(const std::string& _name) const
{
    int fd{};
    std::string name{};
    if(_name.empty())
    {
        name = "/proc/self/exe";
    }
    else
    {
        name = create_memmap().find(_name).name();
    }

    {
        auto it = _elfs.find(name);
        if (it != std::end(_elfs))
        {
            return it->second;
        }
    }

    fd = open(name.c_str(), O_RDONLY);
    if(fd == -1)
    {
        throw process_error{std::string{"Could not open file"} + name};
    }
    // This function takes ownership of the file descriptor
    auto lock = std::unique_lock(_mutex);
    auto it = _elfs.insert_or_assign(std::move(name), elf::elf{elf::create_mmap_loader(fd)}).first;
    return it->second;
}

namespace
{
    symbol create_symbol(const binary& bin, const elf::sym& sym)
    {
        for(const auto& z : bin.zones())
        {
            if(dyntrace::flag(z.perms, perms::exec))
            {
                return symbol{sym.get_name(), sym.get_data().value + z.start, sym.get_data().size};
            }
        }
        throw process_error("Could not create symbol");
    }
}

symbol process::get(const std::string &name, const std::string &lib) const
{
    const elf::elf& e = elf(lib);
    auto symtab = e.get_section(".symtab").as_symtab();
    for(const auto& s : symtab)
    {
        if(s.get_name() == name)
        {
            auto memmap = create_memmap();
            return create_symbol(memmap.find(lib), s);
        }
    }
    throw process_error("Could not find symbol " + name + " in " + lib);
}