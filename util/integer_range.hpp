#ifndef DYNTRACE_UTIL_RANGE_HPP_
#define DYNTRACE_UTIL_RANGE_HPP_

namespace dyntrace
{

    template<typename Int>
    struct integer_range
    {
        Int start{std::numeric_limits<Int>::min()};
        Int end{std::numeric_limits<Int>::max()};

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
    };

    template<typename Int>
    constexpr auto make_integer_range(Int center, Int size) noexcept
    {
        return integer_range<Int>{center < (size >> 1) ? 0llu : center - (size >> 1), center + (size >> 1)};
    }
    using address_range = integer_range<uintptr_t>;

    constexpr auto make_address_range = make_integer_range<uintptr_t>;
}

#endif