
add_executable(dyntraced main.cpp)
target_link_libraries(dyntraced process)
target_include_directories(dyntraced PRIVATE ${CMAKE_SOURCE_DIR})