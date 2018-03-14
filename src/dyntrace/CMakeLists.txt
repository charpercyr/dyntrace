

set(PROTO_FILES proto/command.proto proto/common.proto proto/process.proto)
dyntrace_protobuf_generate_cpp(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
dyntrace_protobuf_generate_python(PROTO_PY_SRCS ${PROTO_FILES})
add_library(proto STATIC ${PROTO_SRCS})
target_link_libraries(proto PUBLIC protobuf)
set_target_properties(proto PROPERTIES
    POSITION_INDEPENDENT_CODE ON
)
add_custom_target(proto_py ALL DEPENDS ${PROTO_PY_SRCS})

set(DYNTRACE_DYNTRACE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})

add_subdirectory(agent)
add_subdirectory(dyntraced)
add_subdirectory(frontends)
add_subdirectory(proto)
add_subdirectory(tracers)

get_target_property(DYNTRACE_AGENT_LIBRARY agent OUTPUT)
configure_file(config.hpp.in config.hpp)
add_library(config INTERFACE)
target_include_directories(config INTERFACE ${CMAKE_CURRENT_BINARY_DIR})