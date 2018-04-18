
include(dyntrace-defs)

macro(dyntrace_option name default)
    if (NOT ${name})
        set(${name} ${default})
    endif()
endmacro()

dyntrace_option(DYNTRACE_TRACER_DIRECTORY lib/dyntrace/tracers)

function(dyntrace_tracer target)
    add_library(${target} MODULE ${ARGN})
    set_target_properties(${target} PROPERTIES
        PREFIX ""
    )
    target_include_directories(${target} PRIVATE ${DYNTRACE_INSTALL_PREFIX}/include)
    install(TARGETS ${target} DESTINATION ${DYNTRACE_TRACER_DIRECTORY})
endfunction()