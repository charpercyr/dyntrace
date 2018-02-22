cmake_minimum_required(VERSION 3.10)

enable_language(CXX ASM)

include(dyntrace.cmake)
include(private.cmake)
include(options.cmake)

set(ARCH x86_64)
set(CMAKE_VERSION 0.1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_FLAGS "-Wall ${CMAKE_CXX_FLAGS}")
set(CMAKE_EXE_LINKER_FLAGS "-L/usr/local/lib ${CMAKE_EXE_LINKER_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG  "-D_DEBUG ${CMAKE_CXX_FLAGS_DEBUG}")

include_directories(include)

install(DIRECTORY include/dyntrace DESTINATION include)
install(FILES dyntrace.cmake DESTINATION share/cmake)

add_subdirectory(examples)
add_subdirectory(src)