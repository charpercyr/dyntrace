
include(FindPkgConfig)

include(arch/${arch}/arch_src.cmake)

pkg_check_modules(CAPSTONE capstone)

add_library(loader SHARED
        arch/asm.hpp
        ${${arch}_src}
        code_allocator.hpp
        error.hpp
        main.cpp)
target_include_directories(loader PRIVATE ${CAPSTONE_INCLUDE_DIRS})
target_link_libraries(loader dl pthread process tracer ${CAPSTONE_LIBRARIES})