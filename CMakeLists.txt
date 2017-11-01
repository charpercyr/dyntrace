cmake_minimum_required(VERSION 3.9)

enable_language(ASM)

set(CMAKE_CXX_STANDARD 17)

add_subdirectory(dyntrace)
add_subdirectory(fasttp)
add_subdirectory(process)
add_subdirectory(tracers)

add_subdirectory(ext)