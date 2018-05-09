cmake_minimum_required(VERSION 3.0)

project(dyntrace)

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

set(link-flags "-L${ARCH_INSTALL}/lib")

set(DYNTRACE_VERSION_MAJOR 0)
set(DYNTRACE_VERSION_MINOR 1)
set(DYNTRACE_VERSION_PATCH 0)
set(DYNTRACE_VERSION ${DYNTRACE_VERSION_MAJOR}.${DYNTRACE_VERSION_MINOR}.${DYNTRACE_VERSION_PATCH})

set(CMAKE_VERSION ${DYNTRACE_VERSION})
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_FLAGS "-Wall -I${ARCH_INSTALL}/include ${link-flags} ${CMAKE_C_FLAGS}")
set(CMAKE_ASM_FLAGS "-Wall ${link-flags} ${CMAKE_ASM_FLAGS}")
set(CMAKE_CXX_FLAGS "-Wall -I${ARCH_INSTALL}/include ${link-flags} ${CMAKE_CXX_FLAGS}")
set(CMAKE_CXX_FLAGS_DEBUG  "-D_DEBUG ${CMAKE_CXX_FLAGS_DEBUG}")
set(CMAKE_INSTALL_RPATH ${CMAKE_INSTALL_PREFIX}/lib ${ARCH_INSTALL}/lib)
set(CMAKE_BUILD_RPATH ${ARCH_INSTALL}/lib)

include_directories(include)

install(DIRECTORY include/dyntrace DESTINATION include)
install(FILES dyntrace.cmake DESTINATION share/cmake)
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/dyntrace-defs.cmake DESTINATION share/cmake)

add_subdirectory(examples)
add_subdirectory(src)

set(CPACK_GENERATOR TGZ)
set(CPACK_SYSTEM_NAME ${CMAKE_SYSTEM_PROCESSOR}-${CMAKE_SYSTEM_NAME})
set(CPACK_PACKAGE_VERSION_MAJOR ${DYNTRACE_VERSION_MAJOR})
set(CPACK_PACKAGE_VERSION_MINOR ${DYNTRACE_VERSION_MINOR})
set(CPACK_PACKAGE_VERSION_PATCH ${DYNTRACE_VERSION_PATCH})
include(CPack)