

if(NOT ARCH)
    execute_process(COMMAND uname -m OUTPUT_VARIABLE ARCH OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

function(chos_add_arch arch)
    foreach (subarch ${ARGN})
        if (ARCH STREQUAL ${subarch})
            set(SUBARCH ${ARCH} PARENT_SCOPE)
            set(ARCH ${arch} PARENT_SCOPE)
            return()
        endif()
    endforeach()
endfunction()

chos_add_arch(x86 i386 x86_64)
chos_add_arch(arm arm aarch64)

include(${ARCH}.cmake OPTIONAL)