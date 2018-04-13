cmake_minimum_required(VERSION 3.0)

enable_language(CXX ASM)

if(NOT ARCH_INSTALL)
    set(ARCH_INSTALL "/usr")
endif()

configure_file(dyntrace-defs.cmake dyntrace-defs.cmake)
list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_BINARY_DIR})

include(arch.cmake)
include(dyntrace.cmake)
include(private.cmake)
include(options.cmake)

set(CMAKE_VERSION 0.1)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "-Wall -I${ARCH_INSTALL}/include -L${ARCH_INSTALL}/lib ${CMAKE_CXX_FLAGS}")
set(CMAKE_ASM_FLAGS "-Wall -L${ARCH_INSTALL}/lib ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -I${ARCH_INSTALL}/include -L${ARCH_INSTALL}/lib ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG  "-D_DEBUG ${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib ${ARCH_INSTALL}/lib)
set(CMAKE_BUILD_RPATH ${ARCH_INSTALL}/lib)

include_directories(include)

install(DIRECTORY include/dyntrace DESTINATION include)
install(FILES dyntrace.cmake DESTINATION share/cmake)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dyntrace-defs.cmake DESTINATION share/cmake)

add_subdirectory(examples)
add_subdirectory(src)