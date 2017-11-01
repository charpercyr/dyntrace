#ifndef DYNTRACE_PROCESS_MEMMAP_HPP_
#define DYNTRACE_PROCESS_MEMMAP_HPP_

#include <functional>
#include <istream>
#include <string_view>
#include <map>

#include "flag.hpp"

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
    template<>
    struct is_flag_enum<Perm> : std::true_type{};

    struct Zone
    {
        uintptr_t start;
        uintptr_t end;
        Perm perm;
        std::string obj;
    };

    class Object
    {
        friend class Memmap;
        using ZoneList = std::vector<Zone>;
    public:
        using iterator = ZoneList::const_iterator;
        using const_iterator = iterator;
        using value_type = Zone;
        using reference_type = Zone&;
        using iterator_category = ZoneList::iterator::iterator_category;

        iterator begin() const noexcept
        {
            return _zones.begin();
        }

        iterator end() const noexcept
        {
            return _zones.end();
        }

        std::string name() const
        {
            return _zones.front().obj;
        }

    private:
        explicit Object(ZoneList&& zones) noexcept;
        ZoneList  _zones;
    };

    class Memmap
    {
        using ObjectMap = std::map<std::string, Object>;
    public:
        static Memmap from_stream(std::istream& in);
        static Memmap from_path(const char* path);
        static Memmap from_path(const std::string& path);
        static Memmap from_pid(pid_t pid);

        using value_type = const Object;
        using reference_type = const Object&;
        using pointer_type = const Object*;

        class iterator
        {
            friend class Memmap;
        public:
            using value_type = Memmap::value_type;
            using reference_type = Memmap::reference_type;
            using pointer_type = Memmap::pointer_type;
            using iterator_category = Memmap::ObjectMap::iterator::iterator_category;

            iterator& operator++() noexcept
            {
                ++_it;
                return *this;
            }

            iterator operator++(int) noexcept
            {
                iterator it = iterator(_it);
                ++_it;
                return it;
            }

            reference_type operator*() const noexcept
            {
                return _it->second;
            }

            pointer_type operator->() const noexcept
            {
                return &_it->second;
            }

            bool operator==(const iterator& it) const noexcept
            {
                return _it == it._it;
            }

            bool operator!=(const iterator& it) const noexcept
            {
                return _it != it._it;
            }

        private:
            iterator(ObjectMap::const_iterator it)
                : _it{it} {}
            ObjectMap::const_iterator _it;
        };
        using const_iterator = iterator;

        iterator begin() const
        {
            return iterator(_objs.begin());
        }

        iterator end() const
        {
            return iterator(_objs.end());
        }

    private:
        explicit Memmap(ObjectMap&& objs) noexcept;
        ObjectMap _objs;
    };
}

#endif