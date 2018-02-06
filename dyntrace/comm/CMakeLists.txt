
add_library(comm INTERFACE)
target_link_libraries(comm INTERFACE boost_system)
target_sources(comm INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}/local.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/server.hpp
)