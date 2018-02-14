cmake_minimum_required(VERSION 3.9)

include(FindPkgConfig)

enable_language(ASM)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
set(CMAKE_CXX_FLAGS "-Wall ${CMAKE_CXX_FLAGS}")

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(CMAKE_CXX_FLAGS "-D_DEBUG ${CMAKE_CXX_FLAGS}")
endif()

execute_process(COMMAND uname -m OUTPUT_VARIABLE arch OUTPUT_STRIP_TRAILING_WHITESPACE)

pkg_check_modules(CAPSTONE capstone)

include_directories(${CMAKE_SOURCE_DIR})

add_subdirectory(arch)
add_subdirectory(dyntrace)
add_subdirectory(examples)
add_subdirectory(fasttp)
add_subdirectory(process)
add_subdirectory(inject)
add_subdirectory(tracers)
add_subdirectory(util)

add_subdirectory(ext)
