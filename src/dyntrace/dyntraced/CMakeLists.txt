
add_executable(dyntraced
    command.cpp command.hpp
    local.hpp
    main.cpp
    message.hpp
    process.cpp process.hpp
    server.hpp
)
target_link_libraries(dyntraced
    boost_log
    boost_program_options
    boost_system
    boost_thread
    config
    inject
    proto
    pthread
    stdc++fs
    util
)
target_compile_definitions(dyntraced PRIVATE BOOST_LOG_DYN_LINK BOOST_LOG_USE_NATIVE_SYSLOG)
if(ARCH STREQUAL arm)
    target_compile_options(dyntraced PRIVATE -Wno-builtin-declaration-mismatch)
endif()

install(TARGETS dyntraced DESTINATION bin)