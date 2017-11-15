add_library(fasttp SHARED
    code_allocator.cpp code_allocator.hpp
    fasttp.cpp fasttp.hpp)
target_link_libraries(fasttp process tracer)