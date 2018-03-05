
dyntrace_shared_library(inject
    ptrace.cpp
)
target_link_libraries(inject boost_log)
target_compile_definitions(inject PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)