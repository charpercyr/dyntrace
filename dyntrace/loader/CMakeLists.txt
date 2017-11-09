
include(arch/${arch}/arch_src.cmake)

add_library(loader SHARED
        asm.hpp
        ${${arch}_src}
        main.cpp)
target_link_libraries(loader pthread process)