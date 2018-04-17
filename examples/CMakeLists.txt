
if(ARCH STREQUAL x86)

    add_executable(bm bm_tracepoint.cpp)
    target_link_libraries(bm benchmark fasttp)

    if(SUBARCH STREQUAL i386)
        set(loop_asm loop32.S)
    else()
        set(loop_asm loop64.S)
    endif()

    add_executable(loop loop.c ${loop_asm})
    target_link_libraries(loop agent)

    add_executable(ptrace ptrace.cpp)
    target_link_libraries(ptrace inject)

endif()

add_executable(foo foo.cpp)
target_link_libraries(foo fasttp)