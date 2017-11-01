
add_library(process STATIC
        elf.cpp elf.hpp
        error.hpp
        flag.hpp
        memmap.cpp memmap.hpp)
target_link_libraries(process elf)