
add_executable(bm bm_tracepoint.cpp)
target_link_libraries(bm benchmark capstone fasttp)