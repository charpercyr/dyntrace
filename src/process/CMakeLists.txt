dyntrace_shared_library(process
    elf.cpp
    memmap.cpp
    process.cpp
)
target_link_libraries(process elf util)