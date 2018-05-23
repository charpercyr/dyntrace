
if(ARCH STREQUAL x86)

    if(SUBARCH STREQUAL i386)
        set(loop_asm loop32.S)
    else()
        set(loop_asm loop64.S)
    endif()
elseif(ARCH STREQUAL arm)
    set(loop_asm looparm.S)
elseif(ARCH STREQUAL powerpc)
    set(loop_asm loopppc.S)
endif()


add_executable(loop loop.c ${loop_asm})
#target_link_libraries(loop agent)

add_executable(foo foo.cpp)
target_link_libraries(foo fasttp)

if(NOT ARCH STREQUAL powerpc)
    add_executable(bm bm_tracepoint.cpp)
    target_link_libraries(bm benchmark fasttp)
endif()

add_executable(ptrace ptrace.cpp)
target_link_libraries(ptrace inject)

add_executable(multithread multithread.cpp)
target_link_libraries(multithread fasttp pthread)