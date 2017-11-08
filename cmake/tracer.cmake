
macro(dyntrace_add_tracer name)
    add_library(${name} MODULE ${ARGN})
endmacro()