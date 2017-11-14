
macro(dyntrace_add_tracer name)
    add_library(${name} MODULE ${ARGN})
    target_link_libraries(${name} PRIVATE tracer)
endmacro()