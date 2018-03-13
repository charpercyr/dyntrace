dyntrace_shared_library(process
    memmap.cpp
    process.cpp
)
target_link_libraries(process elf++ util)