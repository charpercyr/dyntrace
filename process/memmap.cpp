#include "memmap.hpp"

#include <fstream>


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

        sscanf(line.c_str(), "%lx-%lx %s %*s %*s %*s %s\n", &start, &end, perms, name);

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
    for(auto& b : binaries)
    {
        res.insert(std::make_pair(b.first, binary{std::move(b.second)}));
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