
add_executable(bm bm_tracepoint.cpp)
target_link_libraries(bm benchmark fasttp)

add_executable(foo foo.cpp)
target_link_libraries(foo fasttp)

add_executable(loop loop.S loop.c)
target_link_libraries(loop agent)