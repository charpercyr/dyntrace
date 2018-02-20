add_library(agent SHARED
    main.cpp)
target_link_libraries(agent PUBLIC
    boost_log
    comm
    fasttp
    pthread
    stdc++fs
)
target_compile_definitions(agent PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)