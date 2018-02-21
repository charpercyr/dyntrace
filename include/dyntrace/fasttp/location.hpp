/**
 * Resolver classes for addresses in a process.
 */
#ifndef DYNTRACE_FASTTP_LOCATION_HPP_
#define DYNTRACE_FASTTP_LOCATION_HPP_

#include "dyntrace/process/process.hpp"

namespace dyntrace::fasttp
{
    struct location
    {
        virtual ~location() = default;

        virtual void* resolve(const process::process& proc) const = 0;
    };

    /**
     * Resolves to the address given in the constructor
     */
    struct addr_location : location
    {
        void* resolve(const process::process& proc) const override;

        template<typename T>
        explicit addr_location(T* a) noexcept : addr{reinterpret_cast<void*>(a)} {}

        void* addr;
    };

    /**
     * Resolves to the address of the given symbol
     */
    struct symbol_location : location
    {
        void* resolve(const process::process& proc) const override;

        explicit symbol_location(std::string str) noexcept : name{std::move(str)} {}

        std::string name;
    };
}

#endif