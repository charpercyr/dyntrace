#include "tracepoints.hpp"

#include "dyntrace/process/process.hpp"

#include <regex>
#include <dyntrace/fasttp/error.hpp>

using namespace dyntrace;
using namespace dyntrace::agent;

namespace
{
    using symbol_list = std::vector<std::pair<std::string, void*>>;

    symbol_list _find_symbols(const std::regex& r, const elf::elf& e, uintptr_t base)
    {
        auto symtab = e.get_section(".symtab");
        if (!symtab.valid())
            return {};
        symbol_list addrs;
        for (auto &&sym : symtab.as_symtab())
        {
            if(sym.get_data().type() == elf::stt::func)
            {
                if (std::regex_match(sym.get_name(), r))
                {
                    auto addr = reinterpret_cast<void *>(
                        sym.get_data().value + base
                    );
                    addrs.emplace_back(sym.get_name(), addr);
                }
            }
        }
        return addrs;
    }

    symbol_list find_symbols(const std::regex &name)
    {
        return _find_symbols(name, process::process::this_process().elf(), process::process::this_process().base());
    }

    symbol_list find_symbols(const std::regex& name, const std::regex& lib)
    {
        return _find_symbols(name, process::process::this_process().elf(lib), process::process::this_process().base(lib));
    }

    std::regex create_regex_from_filter(const std::string& filter)
    {
        std::string res;
        for(char c : filter)
        {
            if (c == '*')
                res += ".*";
            else if (c == '.')
                res += "\\.";
            else
                res += c;
        }
        return std::regex{res};
    }

    std::vector<std::string> get_tracer_args(const proto::process::add_tracepoint& req)
    {
        std::vector<std::string> res;
        std::copy(req.tracer_args().begin(), req.tracer_args().end(), std::back_inserter(res));
        return res;
    }
}

tracepoint_registry::add_status tracepoint_registry::add(const proto::process::add_tracepoint &req)
{
    tracepoint_group tg;

    if(!req.name().empty())
    {
        if(_groups.find(req.name()) != _groups.end())
            throw tracepoints_error{"Group name " + req.name() + " already exists"};
    }

    symbol_list syms;
    if(req.has_filter())
    {
        std::regex name = req.filter().regex() ? std::regex{req.filter().name()} : create_regex_from_filter(req.filter().name());
        if(req.filter().lib().empty())
            syms = find_symbols(name);
        else
            syms = find_symbols(name, std::regex{req.filter().lib()});
        tg.location = tracepoint_group_filter{req.filter().name() + (req.filter().lib().empty() ? "" : "@" + req.filter().lib())};
    }
    else
    {
        syms = {{"", reinterpret_cast<void *>(req.address())}};
        tg.location = req.address();
    }
    if(syms.empty())
        throw tracepoints_error{"Filter does not match any function"};

    tg.tracer = req.tracer();
    auto& fact = _tracers.get_factory(tg.tracer);
    tg.entry_exit = req.entry_exit();
    tg.tracer_args = get_tracer_args(req);
    if(tg.entry_exit)
        tg.handler = fact.create_entry_exit_handler(tg.tracer_args);
    else
        tg.handler = fact.create_point_handler(tg.tracer_args);

    add_status status;
    for(auto&& sym : syms)
    {
        if(check_sym(sym.second))
        {
            try
            {
                auto tp = fasttp::tracepoint{sym.second, std::ref(tg.handler)};
                tg.tps.push_back(tracepoint{
                    .symbol = (sym.first.empty() ? std::nullopt : std::optional{sym.first}),
                    .failed = false,
                    .tp = std::move(tp)
                });
                ++tg.active;
                continue;
            }
            catch(const std::exception& e)
            {
                status.second.emplace_back(tg.tps.size(), e.what());
            }
        }
        else
            status.second.emplace_back(tg.tps.size(), "tracepoint " + to_hex_string(sym.second) + " already exists");
        tg.tps.push_back(tracepoint{
            .symbol = (sym.first.empty() ? std::nullopt : std::optional{sym.first}),
            .failed = true,
            .tp = {}
        });
    }
    if(tg.active == 0)
        return status;

    if(req.name().empty())
        tg.name = "tp-" + std::to_string(_next_id++);
    else
        tg.name = req.name();

    status.first = tg.name;

    _groups.emplace(tg.name, std::move(tg));

    return status;
}

void tracepoint_registry::remove(const proto::process::remove_tracepoint &req)
{
    using namespace std::string_literals;
    auto it = _groups.find(req.name());
    if(it != _groups.end())
         _groups.erase(it);
    else
        throw tracepoints_error{"Tracepoint "s + req.name() + " does not exist"s};
}

bool tracepoint_registry::check_sym(void *addr)
{
    for(auto&& tg : _groups)
    {
        for(auto&& tp : tg.second.tps)
        {
            if(tp.tp.location() == addr)
                return false;
        }
    }
    return true;
}