
define_property(TARGET PROPERTY OUTPUT BRIEF_DOCS "output name" FULL_DOCS "output name")

function(dyntrace_shared_library target)
    cmake_parse_arguments(ARG "" "DESTINATION" "" ${ARGN})
    if(NOT ARG_DESTINATION)
        set(ARG_DESTINATION lib)
    endif()
    add_library(${target} SHARED ${ARG_UNPARSED_ARGUMENTS})
    set_target_properties(${target} PROPERTIES
        OUTPUT_NAME dyntrace-${target}
        SOVERSION ${CMAKE_VERSION}
        OUTPUT ${CMAKE_INSTALL_PREFIX}/${ARG_DESTINATION}/libdyntrace-${target}.so.${CMAKE_VERSION}
        )
    install(
        TARGETS ${target}
        LIBRARY DESTINATION ${ARG_DESTINATION}
    )
endfunction()