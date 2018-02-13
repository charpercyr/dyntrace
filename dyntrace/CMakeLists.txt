
macro(dyntrace_option var default)
    if(NOT ${var})
        set(${var} ${default})
    endif()
endmacro()

if(${CMAKE_BUILD_TYPE} STREQUAL "Debug")
    set(DYNTRACE_WORKING_DIRECTORY "/tmp/dyntrace")
endif()

dyntrace_option(DYNTRACE_GROUP_NAME dyntrace)
dyntrace_option(DYNTRACE_WORKING_DIRECTORY "/run/dyntrace")
dyntrace_option(DYNTRACE_COMMAND_SOCKET_NAME "command.sock")
dyntrace_option(DYNTRACE_PROCESS_SOCKET_NAME "process.sock")
dyntrace_option(DYNTRACE_LOCK_FILE_NAME "dyntraced.lock")
configure_file(config.hpp.in config.hpp @ONLY)
include_directories(${CMAKE_CURRENT_BINARY_DIR})

find_package(Protobuf REQUIRED)
set(PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
set(PROTO_FILES
    ${PROTO_DIR}/command.proto
    ${PROTO_DIR}/process.proto)
protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
add_library(proto STATIC
    ${PROTO_SRCS}
    ${PROTO_HDRS}
)
target_include_directories(proto PUBLIC ${Protobuf_INCLUDE_DIRS} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(proto PUBLIC ${Protobuf_LIBRAIRIES})

add_subdirectory(comm)
add_subdirectory(dyntraced)
add_subdirectory(frontends)
add_subdirectory(loader)