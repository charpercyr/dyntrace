
add_library(tracer INTERFACE)
target_sources(tracer INTERFACE ${CMAKE_CURRENT_SOURCE_DIR}/tracer.hpp ${CMAKE_CURRENT_SOURCE_DIR}/x86_64.hpp)
target_include_directories(tracer INTERFACE ${CMAKE_CURRENT_SOURCE_DIR})