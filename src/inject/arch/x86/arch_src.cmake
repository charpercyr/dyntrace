
set(x86_src
    arch/x86/executor.cpp arch/x86/executor.hpp
)

if(SUBARCH STREQUAL i386)
    set(x86_src ${x86_src} arch/x86/executor32.S)
else()
    set(x86_src ${x86_src} arch/x86/executor64.S)
endif()