
include(arch/${ARCH}/arch_src.cmake)

dyntrace_shared_library(fasttp
    ${${ARCH}_src}
    code_ptr.hpp
    common.cpp
    arch/tracepoint.hpp
    context.cpp context.hpp
    fasttp.cpp
    reclaimer.cpp reclaimer.hpp)
target_link_libraries(fasttp process pthread ${${ARCH}_lib})
target_include_directories(fasttp PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})