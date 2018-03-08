
dyntrace_shared_library(agent
    main.cpp
    tracer.cpp tracer.hpp
    DESTINATION lib/dyntrace
)
target_link_libraries(agent
    boost_log
    boost_system
    config
    fasttp
    proto
    stdc++fs
)
target_compile_definitions(agent PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)