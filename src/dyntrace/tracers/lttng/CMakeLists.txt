
dyntrace_tracer(lttng lttng.cpp tp.cpp tp.hpp)
target_link_libraries(lttng lttng-ust dl)
target_include_directories(lttng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})