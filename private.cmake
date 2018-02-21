
function(dyntrace_shared_library target)
    add_library(${target} SHARED ${ARGN})
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME dyntrace-${target}
        SOVERSION ${CMAKE_VERSION}
        )
    install(
        TARGETS ${target}
        LIBRARY DESTINATION lib
    )
endfunction()