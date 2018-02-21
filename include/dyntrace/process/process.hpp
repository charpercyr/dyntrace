#ifndef DYNTRACE_PROCESS_PROCESS_HPP_
#define DYNTRACE_PROCESS_PROCESS_HPP_

#include "memmap.hpp"

#include "dyntrace/util/util.hpp"

#include <libelfin/elf/elf++.hh>

#include <map>
#include <memory>
#include <mutex>
#include <sys/types.h>

namespace dyntrace::process
{
    /**
     * Represents a symbol in the processe's memory. The value represents the address in the virtual-space.
     */
    struct symbol
    {
        std::string name;
        uintptr_t value;
        size_t size;
    };

    /**
     * Process handle
     */
    class process
    {
    public:
        explicit process(pid_t pid) noexcept
            : _pid{pid} {}

        static const process& this_process() noexcept;

        /**
         * Returns the current memory map of the process.
         */
        memmap create_memmap() const
        {
            return memmap::from_pid(_pid);
        }

        /**
         * Elf of the executable.
         */
        const elf::elf& elf() const;
        /**
         * Elf of a mapped file that matches the regex.
         */
        const elf::elf& elf(const std::regex& name) const;

        /**
         * Gets a symbol from the executable.
         */
        symbol get(const std::string& sym) const;
        /**
         * Gets a symbol from a mapped file that matches the regex.
         */
        symbol get(const std::string& sym, const std::regex& lib) const;

        /**
         * Base address of the executable region of the process.
         * @return
         */
        uintptr_t base() const;

        pid_t pid() const noexcept
        {
            return _pid;
        }

        std::vector<pid_t> threads() const;

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