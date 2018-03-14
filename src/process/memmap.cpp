#include "dyntrace/process/memmap.hpp"

#include <fstream>
#include <cinttypes>
#include <set>

using dyntrace::address_range;
using namespace dyntrace::process;

memmap memmap::from_stream(std::istream &is) noexcept
{
    std::string line;
    std::map<std::string, std::vector<zone>> binaries;
    while(std::getline(is, line))
    {
        uintptr_t start, end;
        char name[1024]{};
        char perms[5];

        sscanf(line.c_str(), "%" PRIxPTR "-%" PRIxPTR " %s %*s %*s %*s %s\n", &start, &end, perms, name);

        zone z{start, end, permissions::none, name};
        if(perms[0] == 'r')
            z.perms |= permissions::read;
        if(perms[1] == 'w')
            z.perms |= permissions::write;
        if(perms[2] == 'x')
            z.perms |= permissions::exec;
        if(perms[3] == 's')
            z.perms |= permissions::shared;

        binaries[name].push_back(std::move(z));
    }

    memmap::binary_map res;
    for(auto& [name, bin] : binaries)
    {
        res.insert(std::make_pair(name, binary{std::move(bin)}));
    }
    return memmap{std::move(res)};
}

memmap memmap::from_path(const std::string &path)
{
    std::ifstream file(path);
    if(!file)
        throw process_error("Could not open file " + path);
    return from_stream(file);
}

memmap memmap::from_pid(pid_t pid)
{
    return from_path("/proc/" + std::to_string(pid) + "/maps");
}

const binary::zone_list memmap::all_zones() const noexcept
{
    std::vector<zone> res;
    for(const auto& [_, bin] : _binaries)
    {
        (void)_;
        for(const auto& z : bin.zones())
        {
            if(z.size() != 0)
                res.push_back(z);
        }
    }

    std::sort(res.begin(), res.end(), [](const zone& z1, const zone& z2)
    {
        return z1.start < z2.start;
    });

    return res;
}

const std::vector<address_range> memmap::free() const noexcept
{
    auto zones = all_zones();

    if(zones.empty())
    {
        return {{0, std::numeric_limits<uintptr_t>::max()}};
    }

    std::vector<address_range> res;
    address_range begin = {0, zones.front().start};
    if(begin.size() != 0)
        res.push_back(begin);
    for(size_t i = 0; i < zones.size() - 1; i++)
    {
        address_range range = {zones[i].end, zones[i + 1].start};
        if(range.size() != 0)
            res.push_back(std::move(range));
    }
    address_range end = {zones.back().end, std::numeric_limits<uintptr_t>::max()};
    if(end.size() != 0)
        res.push_back(end);

    return res;
}