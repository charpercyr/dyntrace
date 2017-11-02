#ifndef DYNTRACE_UTIL_UTIL_HPP_
#define DYNTRACE_UTIL_UTIL_HPP_

#include <functional>
#include <string>

namespace dyntrace
{
        template<typename Int>
        constexpr Int ceil_div(Int a, Int b) noexcept
        {
            return (a + b - 1) / b;
        }

        template<typename T>
        class resource
        {
        public:
            template<typename FuncType>
            explicit resource(T t, FuncType&& func)
                : _t{std::move(t)}, _cleanup{func} {}
            ~resource() noexcept
            {
                _cleanup(_t);
            }

            operator T() const noexcept
            {
                return _t;
            }

        private:
            T _t;
            std::function<void(T t)> _cleanup;
        };

        std::string realpath(const std::string& path);
        std::string get_executable(pid_t pid);
        pid_t find_process(const std::string& name);
}

#endif