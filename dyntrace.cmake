
function(dyntrace_tracer target)
    add_library(${target} MODULE ${ARGN})
    set_target_properties(${target} PROPERTIES
        PREFIX ""
    )
endfunction()