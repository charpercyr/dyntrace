
dyntrace_tracer(lttng lttng.cpp tp.cpp tp.hpp)
target_link_libraries(lttng lttng-ust dl)
target_compile_options(lttng PRIVATE -I${CMAKE_CURRENT_SOURCE_DIR})