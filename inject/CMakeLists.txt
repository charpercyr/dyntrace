
include(arch/${arch}/arch_src.cmake)

add_library(inject STATIC
        auto_ptr.hpp
        arch/dl.hpp
        arch/target.hpp
        ${${arch}_src}
        dl.hpp
        error.hpp
        injector.cpp injector.hpp
        ptrace.hpp
        remote.hpp
        remote_util.hpp
        )
target_link_libraries(inject PUBLIC process util)