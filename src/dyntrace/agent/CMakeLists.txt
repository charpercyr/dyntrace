
dyntrace_shared_library(agent
    common.hpp
    main.cpp
    tracepoints.cpp tracepoints.hpp
    tracer.cpp tracer.hpp
    DESTINATION lib/dyntrace
    NOSOVERSION
)
target_link_libraries(agent
    boost_log
    boost_system
    config
    dl
    fasttp
    proto
    stdc++fs
)
target_compile_definitions(agent PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)