
add_library(process STATIC
        error.hpp
        memmap.cpp memmap.hpp
        process.cpp process.hpp)
target_link_libraries(process PUBLIC libelfin-dwarf util)