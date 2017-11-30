#ifndef DYNTRACE_FASTTP_OPTIONS_HPP_
#define DYNTRACE_FASTTP_OPTIONS_HPP_

namespace dyntrace
{
    namespace fasttp
    {
        enum class options
        {
            none = 0,
            disable_basic_block = 1,
            disable_thread_safe = 2,
            disable_auto_remove = 4
        };
    }
    template<>
    struct is_flag_enum<fasttp::options> : std::true_type{};
}

#endif