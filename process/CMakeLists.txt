
add_library(process STATIC
        error.hpp
        flag.hpp
        memmap.cpp memmap.hpp
        util.hpp)
target_link_libraries(process PUBLIC libelfin-dwarf)