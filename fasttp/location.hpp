#ifndef DYNTRACE_FASTTP_LOCATION_HPP_
#define DYNTRACE_FASTTP_LOCATION_HPP_

#include <process/process.hpp>

namespace dyntrace::fasttp
{
    struct location
    {
        virtual ~location() = default;

        virtual void* resolve(const process::process& proc) const = 0;
    };

    struct addr_location : location
    {
        void* resolve(const process::process& proc) const override;

        template<typename T>
        explicit addr_location(T* a) noexcept : addr{reinterpret_cast<void*>(a)} {}

        void* addr;
    };

    struct symbol_location : location
    {
        void* resolve(const process::process& proc) const override;

        explicit symbol_location(std::string str) noexcept : name{std::move(str)} {}

        std::string name;
    };
}

#endif