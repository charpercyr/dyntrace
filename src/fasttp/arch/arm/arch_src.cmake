set(arm_src
    arch/arm/code_allocator.hpp
    arch/arm/context.cpp arch/arm/context.hpp
    arch/arm/out_of_line.cpp arch/arm/out_of_line.hpp
    arch/arm/tracepoint.cpp arch/arm/tracepoint.hpp
    arch/arm/tracepoint.S
)

set(
    arm_lib
    capstone
)