
define_property(TARGET PROPERTY OUTPUT BRIEF_DOCS "output name" FULL_DOCS "output name")

function(dyntrace_shared_library target)
    add_library(${target} SHARED ${ARGN})
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME dyntrace-${target}
        SOVERSION ${CMAKE_VERSION}
        OUTPUT ${CMAKE_INSTALL_PREFIX}/lib/libdyntrace-${target}.so.${CMAKE_VERSION}
        )
    install(
        TARGETS ${target}
        LIBRARY DESTINATION lib
    )
endfunction()