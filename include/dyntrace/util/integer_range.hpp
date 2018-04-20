/**
 * Integer ranges types. Useful to represent addresses or offset ranges
 */

#ifndef DYNTRACE_UTIL_RANGE_HPP_
#define DYNTRACE_UTIL_RANGE_HPP_

#include "util.hpp"

#include <limits>

namespace dyntrace
{

    template<typename Int>
    struct integer_range
    {
        Int start;
        Int end;

        constexpr integer_range(Int _start, Int _end) noexcept
            : start{_start}, end{_end}
        {
            if(start > end)
                std::swap(start, end);
        }

        constexpr integer_range() noexcept
            : integer_range{0, 0} {}

        /**
         * True if v >= start and v <= end
         */
        constexpr bool contains(Int v) const noexcept
        {
            return v >= start && v < end;
        }

        /**
         * True if r is completely contained in the range
         */
        template<typename Int2>
        constexpr bool contains(const integer_range<Int2> &r) const noexcept
        {
            return r.start >= start && r.end <= end;
        }

        /**
         * True if r is partially contained in the range
         */
        template<typename Int2>
        constexpr bool crosses(const integer_range<Int2>& r) const noexcept
        {
            return (r.start < start && r.end > start) || (r.start < end && r.end > end);
        }

        constexpr Int size() const noexcept
        {
            return end - start;
        }

        constexpr integer_range<Int> intersection(const integer_range<Int>& r) const noexcept
        {
            if(!contains(r) && !r.contains(*this) && !crosses(r))
                return {0, 0};
            return {max(start, r.start), min(end, r.end)};
        }

        /**
         * True if the range is not empty
         */
        explicit constexpr operator bool() const noexcept
        {
            return size() != 0;
        }

        template<typename Int2>
        constexpr bool operator==(const integer_range<Int2>& r) const noexcept
        {
            return start == r.start && end == r.end;
        }

        template<typename Int2>
        constexpr bool operator!=(const integer_range<Int2>& r) const noexcept
        {
            return start != r.start || end != r.end;
        }

        template<typename Int2>
        constexpr bool operator<(const integer_range<Int2>& r) const noexcept
        {
            if(start != r.start)
                return start < r.start;
            else
                return end < r.end;
        }
    };

    /**
     * Creates a range around center of size size. The range is [center - size/2, center + size/2)
     */
    template<typename Int>
    constexpr auto integer_range_around(Int center, Int size) noexcept
    {
        // TODO overflow and underflow safe
        size >>= 1;
        return integer_range<Int>{
            center < std::numeric_limits<Int>::min() + size ? std::numeric_limits<Int>::min() : center - size,
            center > std::numeric_limits<Int>::max() - size ? std::numeric_limits<Int>::max() : center + size
        };
    }

    using address_range = integer_range<uintptr_t>;
    constexpr auto address_range_around = integer_range_around<uintptr_t>;
}

#endif