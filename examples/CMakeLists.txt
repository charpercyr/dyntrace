
add_executable(bm bm_tracepoint.cpp)
target_link_libraries(bm benchmark fasttp)

add_executable(foo foo.cpp)
target_link_libraries(foo fasttp)

if(ARCH STREQUAL x86)
    if(SUBARCH STREQUAL i386)
        set(loop_asm loop32.S)
    else()
        set(loop_asm loop64.S)
    endif()
endif()

add_executable(loop loop.c ${loop_asm})

add_executable(ptrace ptrace.cpp)
target_link_libraries(ptrace inject)