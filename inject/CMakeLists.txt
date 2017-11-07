
include(arch/${arch}/arch_src.cmake)

add_library(inject STATIC
        auto_ptr.hpp
        arch/ptrace.hpp
        ${${arch}_src}
        error.hpp
        injector.cpp injector.hpp
        ptrace.hpp
        remote_util.hpp
        )
target_link_libraries(inject PUBLIC process util)