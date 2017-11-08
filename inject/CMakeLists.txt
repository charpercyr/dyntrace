
include(arch/${arch}/arch_src.cmake)

add_library(inject STATIC
        auto_ptr.hpp
        arch/target.hpp
        ${${arch}_src}
        error.hpp
        injector.hpp
        ptrace.hpp
        remote.hpp
        remote_util.hpp
        )
target_link_libraries(inject PUBLIC process util)