
dyntrace_shared_library(dlwrapper dlwrapper.c DESTINATION lib/dyntrace NOSOVERSION)
target_link_libraries(dlwrapper dl)