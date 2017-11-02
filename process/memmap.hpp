#ifndef DYNTRACE_PROCESS_MEMMAP_HPP_
#define DYNTRACE_PROCESS_MEMMAP_HPP_

#include <cstring>
#include <functional>
#include <istream>
#include <string>
#include <map>

#include "error.hpp"

#include <util/flag.hpp>
#include <util/util.hpp>

namespace dyntrace::process
{
    enum class perms
    {
        none = 0,
        read = 1,
        write = 2,
        exec = 4,
        shared = 8
    };

    struct zone
    {
        uintptr_t start;
        uintptr_t end;
        perms perms;
        std::string bin;

        constexpr uintptr_t size() const noexcept
        {
            return end - start;
        }
    };

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

        const binary& find(const std::string& name) const
        {
            for(const auto& b : _binaries)
            {
                if(strstr(b.first.c_str(), name.c_str()) != nullptr)
                    return b.second;
            }
            throw process_error("Could not find name " + name);
        }

    private:
        explicit memmap(binary_map&& binaries) noexcept
            : _binaries{std::move(binaries)} {}
        binary_map _binaries;
    };
}

namespace dyntrace
{
    template<>
    struct is_flag_enum<process::perms> : std::true_type{};
}

#endif