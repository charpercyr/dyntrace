

add_executable(dyntraced
    command.cpp command.hpp
    main.cpp
    process.cpp process.hpp
)
target_compile_definitions(dyntraced PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)
target_link_libraries(dyntraced PRIVATE
    comm
    boost_log
    boost_log_setup
    boost_program_options
    boost_system
    boost_thread
    stdc++fs
    pthread
)
target_include_directories(dyntraced PRIVATE ${CMAKE_CURRENT_BINARY_DIR})