
add_library(arch INTERFACE)
target_sources(arch INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/arch.hpp ${CMAKE_CURRENT_SOURCE_DIR}/${arch}.hpp)