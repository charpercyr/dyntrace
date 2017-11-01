#ifndef DYNTRACE_PROCESS_UTIL_HPP_
#define DYNTRACE_PROCESS_UTIL_HPP_

#include <functional>
#include <type_traits>

namespace dyntrace
{
    namespace process
    {
        struct RunOnce
        {
            template<typename FuncType>
            explicit RunOnce(FuncType&& func) noexcept(std::is_nothrow_invocable<FuncType>::value)
            {
                func();
            }
        };

        class Cleanup
        {
        public:
            template<typename FuncType>
            explicit Cleanup(FuncType&& func) noexcept
                : _func{func} {}

            ~Cleanup() noexcept
            {
                if(_func)
                    _func();
            }

            void cancel() noexcept
            {
                _func = nullptr;
            }

        private:
            std::function<void()> _func;
        };
    }
}

#endif