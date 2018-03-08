
include(arch/${ARCH}/arch_src.cmake)

dyntrace_shared_library(inject
    ${${ARCH}_src}
    arch/executor.hpp
    executor.cpp
    injector.cpp
    ptrace.cpp
)
target_link_libraries(inject boost_log process)
target_compile_definitions(inject PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)

add_subdirectory(dlwrapper)

get_target_property(DYNTRACE_DLWRAPPER_LIBRARY dlwrapper OUTPUT)
configure_file(config.hpp.in config.hpp)
target_include_directories(inject PRIVATE ${CMAKE_CURRENT_BINARY_DIR})