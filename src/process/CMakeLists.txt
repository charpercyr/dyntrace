
add_library(elf++ SHARED IMPORTED)
set_target_properties(elf++ PROPERTIES IMPORTED_LOCATION /usr/local/lib/libelf++.so)

dyntrace_shared_library(process
    memmap.cpp
    process.cpp
)
target_link_libraries(process elf++ util)