
add_executable(dyntraced main.cpp)
target_link_libraries(dyntraced comm boost_program_options stdc++fs pthread boost_thread)