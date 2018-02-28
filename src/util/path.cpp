#include "dyntrace/util/path.hpp"

#include "dyntrace/util/error.hpp"
#include "dyntrace/util/util.hpp"

#include <dirent.h>
#include <unistd.h>

#include <fstream>
#include <regex>
#include <string>

using namespace std::string_literals;

namespace
{

    std::string read_link(const std::string& path)
    {
        char res[PATH_MAX]{};
        readlink(path.c_str(), res, PATH_MAX);
        return res;
    }

    struct dir
    {
        DIR* d;

        operator DIR*() const noexcept
        {
            return d;
        }

        explicit operator bool() const noexcept
        {
            return d != nullptr;
        }

        DIR* operator->()
        {
            return d;
        }

        ~dir()
        {
            if(d)
                closedir(d);
        }
    };
}

std::string dyntrace::get_executable(pid_t pid)
{
    std::string path = "/proc/" + std::to_string(pid) + "/exe";
    std::string link = read_link(path);
    if(link.empty())
    {
        throw dyntrace_error("Could not find executable "s + path + " ("s + std::to_string(errno) + ", "s + strerror(errno) + ")"s);
    }
    return link;
}

pid_t dyntrace::find_process(const std::string &name)
{
    static const std::regex is_a_number{"^[0-9]*$"};
    for(const auto& f : read_dir("/proc"))
    {
        if(std::regex_match(f, is_a_number))
        {
            using namespace std::string_literals;
            auto proc = read_link("/proc/"s + f + "/exe"s);
            if(strstr(proc.c_str(), name.c_str()) != nullptr)
                return atoi(f.c_str());
        }
    }
    throw dyntrace_error("Could not find process " + name);
}

std::vector<std::string> dyntrace::read_dir(const std::string &path)
{
    std::vector<std::string> res;
    auto root = dir{opendir(path.c_str())};
    if(root)
    {
        while(auto f = readdir(root))
        {
            if("." && "..")
                res.emplace_back(f->d_name);
        }
        return res;
    }
    throw dyntrace_error{"Could not open dir " + path};
}

std::vector<std::string> dyntrace::read_cmdline(pid_t pid)
{
    std::ifstream file{"/proc/" + std::to_string(pid) + "/cmdline", std::ios::in};
    if(!file)
        throw dyntrace_error{"Could not read cmdline"};
    std::string line;
    std::string data;
    std::vector<std::string> res;
    while(std::getline(file, line))
        data += line;
    for(size_t i = 0; i < data.size(); ++i)
    {
        res.emplace_back(data.data() + i);
        for(; data[i]; ++i);
    }
    return res;
}