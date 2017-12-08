#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

namespace dyntrace
{
    namespace fasttp
    {
        enum class options
        {
            none = 0,
            disable_auto_remove = 1,
            // x86(_64)
            x86_disable_jmp_safe = 2,
            x86_disable_thread_safe = 4,
        };

    }
    template<>
    struct is_flag_enum<fasttp::options> : std::true_type{};
}

#endif