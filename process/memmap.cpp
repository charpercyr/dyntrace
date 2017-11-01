#include "memmap.hpp"

#include <fstream>
#include <sstream>

#include "error.hpp"

using namespace dyntrace::process;

Memmap Memmap::from_stream(std::istream &in)
{
    std::map<std::string, std::vector<Zone>> zones;
    std::string line;
    while(std::getline(in, line))
    {
        char perm[5]{};
        char obj[1024]{};
        uintptr_t start, end;
        sscanf(line.c_str(), "%lx-%lx %s %*s %*s %*s %s", &start, &end, perm, obj);
        Zone z{start, end, Perm::none, obj};
        if(perm[0] == 'r')
            z.perm |= Perm::read;
        if(perm[1] == 'w')
            z.perm |= Perm::write;
        if(perm[2] == 'x')
            z.perm |= Perm::exec;
        if(perm[3] == 's')
            z.perm |= Perm::shared;

        auto it = zones.find(z.obj);
        if(it == zones.end())
        {
            std::string zobj = z.obj;
            zones.insert(std::make_pair(zobj, std::vector<Zone>{std::move(z)}));
        }
        else
            it->second.push_back(std::move(z));
    }

    ObjectMap objs;
    for(auto& [n, obj] : zones)
    {
        objs.insert(std::make_pair(n, Object(std::move(obj))));
    }
    return Memmap(std::move(objs));
}

Memmap Memmap::from_path(const char *path)
{
    std::ifstream file(path);
    if(!file)
    {
        throw ProcessError("Could not open file");
    }
    return from_stream(file);
}

Memmap Memmap::from_path(const std::string& path)
{
    return from_path(path.c_str());
}

Memmap Memmap::from_pid(pid_t pid)
{
    std::ostringstream path;
    path << "/proc/" << pid << "/maps";
    return from_path(path.str());
}

Memmap::Memmap(ObjectMap &&objs) noexcept
    : _objs(std::move(objs)) {}

Object::Object(ZoneList &&zones) noexcept
    : _zones(std::move(zones)) {}