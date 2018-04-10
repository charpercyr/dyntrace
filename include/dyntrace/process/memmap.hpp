#ifndef DYNTRACE_PROCESS_MEMMAP_HPP_
#define DYNTRACE_PROCESS_MEMMAP_HPP_

#include "error.hpp"

#include "dyntrace/util/flag.hpp"
#include "dyntrace/util/path.hpp"
#include "dyntrace/util/integer_range.hpp"
#include "dyntrace/util/util.hpp"

#include <cstring>
#include <functional>
#include <istream>
#include <regex>
#include <string>
#include <map>

namespace dyntrace::process
{
    /**
     * Permissions on a region. Is a flag enum (see util/flag.hpp).
     */
    enum class permissions
    {
        none = 0,
        read = 1,
        write = 2,
        exec = 4,
        shared = 8
    };

    /**
     * Memory zone of a process
     */
    struct zone : address_range
    {
        zone(uintptr_t start, uintptr_t end, permissions _perms, std::string _bin) noexcept
            : address_range{start, end}, perms{_perms}, bin{std::move(_bin)} {}
        permissions perms;
        std::string bin;
    };

    /**
     * Mapped binary in a process.
     */
    class binary
    {
        friend class memmap;
    public:
        using zone_list = std::vector<zone>;

        const zone_list& zones() const noexcept
        {
            return _zones;
        }

        const std::string& name() const noexcept
        {
            return _zones[0].bin;
        }

    private:
        explicit binary(zone_list&& zones) noexcept
            : _zones{std::move(zones)} {}
        zone_list _zones;
    };

    /**
     * Memory map of a process
     */
    class memmap
    {
    public:
        using binary_map = std::map<std::string, binary>;

        static memmap from_stream(std::istream& is) noexcept;
        static memmap from_path(const std::string& path);
        static memmap from_pid(pid_t pid);

        const binary_map& binaries() const noexcept
        {
            return _binaries;
        }

        const binary::zone_list all_zones() const noexcept;

        const binary& find(const std::regex& name) const
        {
            for(const auto& b : _binaries)
            {
                if(std::regex_search(b.first, name))
                    return b.second;
            }
            throw process_error("Could not find name");
        }

        /**
         * Returns a list of ranges that are not used by the process.
         * May not be all mappable because of kernel reserved addresses.
         * @return
         */
        const std::vector<address_range> free() const noexcept;

    private:
        explicit memmap(binary_map&& binaries) noexcept
            : _binaries{std::move(binaries)} {}
        binary_map _binaries;
    };
}

namespace dyntrace
{
    template<>
    struct is_flag_enum<process::permissions> : std::true_type{};
}

#endif