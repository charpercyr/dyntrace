
macro(dyntrace_option var default)
    if(NOT ${var})
        set(${var} ${default})
    endif()
endmacro()

dyntrace_option(DYNTRACE_GROUP_NAME dyntrace)
dyntrace_option(DYNTRACE_WORKING_DIRECTORY "/run/dyntrace")
dyntrace_option(DYNTRACE_COMMAND_SOCKET_NAME "command.sock")
dyntrace_option(DYNTRACE_PROCESS_SOCKET_NAME "process.sock")
dyntrace_option(DYNTRACE_LOCK_FILE_NAME "dyntraced.lock")
configure_file(config.hpp.in config.hpp @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

add_subdirectory(comm)
add_subdirectory(dyntraced)
add_subdirectory(frontends)
add_subdirectory(loader)