#ifndef DYNTRACE_PROCESS_PROCESS_HPP_
#define DYNTRACE_PROCESS_PROCESS_HPP_

#include <dwarf++.hh>
#include <elf++.hh>

#include <map>
#include <memory>
#include <mutex>
#include <sys/types.h>

#include "memmap.hpp"

#include <util/util.hpp>

namespace dyntrace::process
{
    struct symbol
    {
        std::string name;
        uintptr_t value;
        size_t size;
    };

    class process
    {
    public:
        explicit process(pid_t pid) noexcept
            : _pid{pid} {}

        memmap create_memmap() const
        {
            return memmap::from_pid(_pid);
        }

        const elf::elf& elf() const;
        const elf::elf& elf(const std::regex& name) const;
        dwarf::dwarf dwarf() const;


        symbol get(const std::string& sym) const;
        symbol get(const std::string& sym, const std::regex& lib) const;

        uintptr_t base() const;

        pid_t pid() const noexcept
        {
            return _pid;
        }

    private:

        const elf::elf& _elf(const std::string& path) const;
        symbol _get(const std::string& sym, const binary& bin) const;

        pid_t _pid;
        // We cache loaded elf (they should not change)
        mutable std::mutex _mutex;
        mutable std::map<std::string, elf::elf> _elfs;
    };
}

#endif