
include(CheckIncludeFiles)

set(CMAKE_REQUIRED_FLAGS -ldl)
check_include_files(lttng/tracepoint.h HAVE_LTTNG)
unset(CMAKE_REQUIRED_FLAGS)

if(HAVE_LTTNG)
    dyntrace_tracer(lttng lttng.cpp tp.cpp tp.hpp)
    target_link_libraries(lttng lttng-ust dl)
    target_include_directories(lttng PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
endif()