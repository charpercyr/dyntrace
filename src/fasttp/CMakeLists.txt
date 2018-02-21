
include(arch/${ARCH}/arch_src.cmake)

dyntrace_shared_library(fasttp
    ${${ARCH}_src}
    arch/tracepoint.hpp
    context.cpp
    fasttp.cpp
    location.cpp
    reclaimer.cpp)
target_link_libraries(fasttp capstone process pthread )