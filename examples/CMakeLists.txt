
if(ARCH STREQUAL x86 AND SUBARCH STREQUAL x86_64)
    add_executable(bm bm_tracepoint.cpp)
    target_link_libraries(bm benchmark fasttp)

    add_executable(foo foo.cpp)
    target_link_libraries(foo fasttp)

    add_executable(loop loop.S loop.c)
    #target_link_libraries(loop dl)

    add_executable(ptrace ptrace.cpp)
    target_link_libraries(ptrace inject)
endif()