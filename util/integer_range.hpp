#ifndef DYNTRACE_UTIL_RANGE_HPP_
#define DYNTRACE_UTIL_RANGE_HPP_

#include <limits>

#include "util.hpp"

namespace dyntrace
{

    template<typename Int>
    struct integer_range
    {
        Int start;
        Int end;

        constexpr integer_range(Int _start = std::numeric_limits<Int>::min(), Int _end = std::numeric_limits<Int>::max())
            : start{_start}, end{_end}
        {
            if(start > end)
                std::swap(start, end);
        }

        constexpr bool contains(Int v) const noexcept
        {
            return v >= start && v < end;
        }

        template<typename Int2>
        constexpr bool contains(const integer_range<Int2> &r) const noexcept
        {
            return r.start >= start && r.end <= end;
        }

        template<typename Int2>
        constexpr bool crosses(const integer_range<Int2>& r) const noexcept
        {
            return (r.start < start && r.end > start) || (r.start < end && r.end > end);
        }

        constexpr Int size() const noexcept
        {
            return end - start;
        }

        integer_range<Int> intersection(const integer_range<Int>& r) const noexcept
        {
            if(!contains(r) && !r.contains(*this) && !crosses(r))
                return {0, 0};
            return {max(start, r.start), min(end, r.end)};
        }

        constexpr operator bool() const noexcept
        {
            return size() != 0;
        }
    };

    template<typename Int>
    constexpr auto integer_range_around(Int center, Int size) noexcept
    {
        return integer_range<Int>{center < (size >> 1) ? 0llu : center - (size >> 1), center + (size >> 1)};
    }
    using address_range = integer_range<uintptr_t>;

    constexpr auto address_range_around = integer_range_around<uintptr_t>;
}

#endif