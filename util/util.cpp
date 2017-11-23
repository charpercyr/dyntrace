#include "util.hpp"

#include <dirent.h>
#include <unistd.h>

#include <fstream>
#include <regex>

#include "../process/error.hpp"

using namespace std::string_literals;

namespace
{

    std::string read_link(const std::string& path)
    {
        char res[PATH_MAX]{};
        readlink(path.c_str(), res, PATH_MAX);
        return res;
    }
}


std::string dyntrace::realpath(const std::string &path)
{
    char res[PATH_MAX];
    ::realpath(path.c_str(), res);
    return res;
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
    auto root = raii<DIR*>{opendir("/proc"), [](auto d)
    {
        closedir(d);
    }};
    if(root)
    {
        while(auto dir = readdir(root))
        {
            if(std::regex_match(dir->d_name, is_a_number))
            {
                using namespace std::string_literals;
                auto proc = read_link("/proc/"s + dir->d_name + "/exe"s);
                if(strstr(proc.c_str(), name.c_str()) != nullptr)
                    return atoi(dir->d_name);
            }
        }
    }
    throw dyntrace_error("Could not find process " + name);
}

void dyntrace::hexdump(void *addr, size_t size) noexcept
{
    auto data = reinterpret_cast<uint8_t*>(addr);
    for(size_t i = 0; i < size;)
    {
        printf("%p: ", data + i);
        for(size_t j = 0; j < 16 && i < size; ++i, ++j)
        {
            printf("%.2x ", static_cast<uint32_t>(data[i]) & 0xff);
        }
        printf("\n");
    }
}