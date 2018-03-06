
add_executable(bm bm_tracepoint.cpp)
target_link_libraries(bm benchmark fasttp)

add_executable(foo foo.cpp)
target_link_libraries(foo fasttp)

add_executable(loop loop.S loop.c)

add_executable(ptrace ptrace.cpp)
target_link_libraries(ptrace inject)

configure_file(dyntrace-start.in ${CMAKE_BINARY_DIR}/dyntrace-start @ONLY)