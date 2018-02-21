#include "dyntrace/process/process.hpp"

#include <fcntl.h>

using namespace dyntrace::process;

namespace
{
    symbol create_symbol(const binary& bin, const elf::sym& sym)
    {
        for(const auto& z : bin.zones())
        {
            if(dyntrace::flag(z.perms, permissions::exec))
            {
                return symbol{sym.get_name(), sym.get_data().value + z.start, sym.get_data().size};
            }
        }
        throw process_error("Could not create symbol");
    }
}

const process& process::this_process() noexcept
{
    static process proc{getpid()};
    return proc;
}

const elf::elf& process::elf() const
{
    return _elf(get_executable(_pid));
}

const elf::elf& process::elf(const std::regex& name) const
{
    auto memmap = create_memmap();
    return _elf(memmap.find(name).name());
}

symbol process::get(const std::string &sym) const
{
    auto memmap = create_memmap();
    const auto& bin = memmap.binaries().at(get_executable(_pid));
    return _get(sym, bin);
}

symbol process::get(const std::string &sym, const std::regex &lib) const
{
    auto memmap = create_memmap();
    const auto& bin = memmap.find(lib);
    return _get(sym, bin);
}

uintptr_t process::base() const
{
    auto memmap = create_memmap();
    const auto& bin = memmap.binaries().at(get_executable(_pid));
    for(const auto& z: bin.zones())
    {
        if (flag(z.perms, permissions::exec))
            return z.start;
    }
    throw process_error("Could not find process executable base");
}

const elf::elf& process::_elf(const std::string &path) const
{
    auto it = _elfs.find(path);
    if (it != std::end(_elfs))
    {
        return it->second;
    }
    // This function takes ownership of the file descriptor
    int fd = open(path.c_str(), O_RDONLY);
    if(fd == -1)
    {
        throw process_error{std::string{"Could not open file"} + path};
    }
    auto lock = std::unique_lock(_mutex);
    it = _elfs.insert_or_assign(std::move(path), elf::elf{elf::create_mmap_loader(fd)}).first;
    return it->second;
}

symbol process::_get(const std::string &sym, const binary &bin) const
{
    const auto& e = _elf(bin.name());
    auto symtab = e.get_section(".symtab").as_symtab();
    for(const auto& s : symtab)
    {
        if(s.get_name() == sym)
        {
            return create_symbol(bin, s);
        }
    }
    throw process_error("Could not find symbol " + sym);
}

std::vector<pid_t> process::threads() const
{
    std::vector<pid_t> res;
    for(const auto& f : read_dir("/proc/" + std::to_string(_pid) + "/task"))
    {
        if(f != "." && f != "..")
            res.emplace_back(atoi(f.c_str()));
    }
    return res;
}