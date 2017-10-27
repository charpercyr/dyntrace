#ifndef DYNTRACE_PROCESS_MEMMAP_HPP_
#define DYNTRACE_PROCESS_MEMMAP_HPP_

#include <functional>
#include <istream>
#include <string_view>
#include <map>

namespace dyntrace::process
{
    enum class Perm
    {
        none = 0,
        read = 1,
        write = 2,
        exec = 4,
        shared = 8
    };

    struct Zone
    {
        uintptr_t _start;
        uintptr_t _end;
    };

    class Memmap;

    class ZoneView
    {
        friend class Memmap;
    public:

    private:
        Memmap& _memmap;
    };

    class ObjectView
    {
        friend class Memmap;
    public:

    private:
        Memmap& _memmap;
        std::function<bool(const std::string& name)> _filter;
    };

    class Memmap
    {
        friend class ZoneView;
        friend class ObjectView;
    public:
        Memmap from_stream(std::istream& in);
        Memmap from_path(const char* path);
        Memmap from_pid(pid_t pid);

        ZoneView zones() const;
        ObjectView objects() const;

    private:
        using ZoneMap = std::map<std::string, Zone>;
        Memmap(ZoneMap&& zones);
        ZoneMap _zones;
    };
}

#endif