
add_library(comm INTERFACE)
target_sources(comm INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/local.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/message.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/server.hpp
)
target_link_libraries(comm INTERFACE boost_system proto protobuf)