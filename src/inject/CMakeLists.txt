
include(arch/${ARCH}/arch_src.cmake)

dyntrace_shared_library(inject
    ${${ARCH}_src}
    executor.cpp arch/executor.hpp
    ptrace.cpp
)
target_link_libraries(inject boost_log process)
target_compile_definitions(inject PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)